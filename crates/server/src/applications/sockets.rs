use super::{Endpoint, LOCAL_ADDRESS_LIMIT, SOCKET_LIMIT};
use anyhow::{Result, bail, ensure};
use einblick_core::ApplicationReason;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

pub(super) fn discover() -> (Vec<Endpoint>, Vec<ApplicationReason>, bool, Vec<String>) {
    let mut sockets = vec![];
    let mut reasons = vec![];
    let mut successes = 0;
    let mut diagnostics = vec![];
    for family in [libc::AF_INET, libc::AF_INET6] {
        for protocol in [6, 17] {
            let before = sockets.len();
            match dump(family as u8, protocol, &mut sockets) {
                Ok(limited) => {
                    successes += 1;
                    if limited {
                        reasons.push(ApplicationReason::ScanLimit);
                    }
                    for endpoint in sockets[before..]
                        .iter()
                        .filter(|s| s.interface_index != 0 && s.interface.is_none())
                        .take(4)
                    {
                        reasons.push(ApplicationReason::CollectorUnavailable);
                        let family = if family == libc::AF_INET {
                            "IPv4"
                        } else {
                            "IPv6"
                        };
                        let protocol = if protocol == 6 { "TCP" } else { "UDP" };
                        diagnostics.push(format!("{family} {protocol}: interface index {} unresolved; socket excluded from attribution", endpoint.interface_index));
                    }
                }
                Err(error) => {
                    reasons.push(ApplicationReason::CollectorUnavailable);
                    let family = if family == libc::AF_INET {
                        "IPv4"
                    } else {
                        "IPv6"
                    };
                    let protocol = if protocol == 6 { "TCP" } else { "UDP" };
                    diagnostics.push(format!("{family} {protocol} socket scan: {error:#}"));
                }
            }
        }
    }
    reasons.sort();
    reasons.dedup();
    (sockets, reasons, successes > 0, diagnostics)
}

fn dump(family: u8, protocol: u8, sockets: &mut Vec<Endpoint>) -> Result<bool> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    ensure!(
        raw >= 0,
        "open socket diagnostics: {}",
        std::io::Error::last_os_error()
    );
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 500_000,
    };
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } == 0,
        "set diagnostic timeout"
    );
    let mut destination: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    destination.nl_family = libc::AF_NETLINK as u16;
    let mut request = [0u8; 72];
    request[0..4].copy_from_slice(&72u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[16] = family;
    request[17] = protocol;
    request[18] = 0xff;
    let states: u32 = if protocol == 6 { 1 << 10 } else { u32::MAX }; // TCP_LISTEN
    request[20..24].copy_from_slice(&states.to_ne_bytes());
    request[64..72].fill(0xff); // INET_DIAG_NOCOOKIE
    ensure!(
        unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                &destination as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&destination) as libc::socklen_t,
            )
        } == request.len() as isize,
        "request socket diagnostics: {}",
        std::io::Error::last_os_error()
    );
    let started = Instant::now();
    let mut buffer = [0u8; 65536];
    let mut limited = false;
    loop {
        ensure!(
            started.elapsed() < Duration::from_secs(1),
            "diagnostic dump timed out"
        );
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut source_len = std::mem::size_of_val(&source) as libc::socklen_t;
        let size = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                &mut source as *mut _ as *mut libc::sockaddr,
                &mut source_len,
            )
        };
        ensure!(
            size >= 0,
            "receive socket diagnostics: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            size as usize <= buffer.len() && source.nl_pid == 0,
            "invalid diagnostic sender or truncated datagram"
        );
        let bytes = &buffer[..size as usize];
        let mut at = 0;
        while at + 16 <= bytes.len() {
            let len = u32::from_ne_bytes(bytes[at..at + 4].try_into()?) as usize;
            ensure!(
                len >= 16 && at + len <= bytes.len(),
                "invalid netlink message length"
            );
            let kind = u16::from_ne_bytes(bytes[at + 4..at + 6].try_into()?);
            let flags = u16::from_ne_bytes(bytes[at + 6..at + 8].try_into()?);
            ensure!(flags & 0x10 == 0, "interrupted diagnostic dump");
            ensure!(
                u32::from_ne_bytes(bytes[at + 8..at + 12].try_into()?) == 1,
                "unexpected diagnostic sequence"
            );
            let payload = &bytes[at + 16..at + len];
            match kind {
                3 => {
                    if payload.len() >= 4 {
                        ensure!(
                            i32::from_ne_bytes(payload[..4].try_into()?) == 0,
                            "diagnostic dump failed"
                        );
                    }
                    return Ok(limited);
                }
                2 => {
                    ensure!(payload.len() >= 4, "short diagnostic kernel error");
                    let code = i32::from_ne_bytes(payload[..4].try_into()?);
                    if code != 0 {
                        bail!(
                            "diagnostic kernel error: {}",
                            std::io::Error::from_raw_os_error(code.saturating_neg())
                        );
                    }
                }
                20 => {
                    let endpoint = parse_endpoint(payload, protocol)?;
                    if endpoint.port != 0 {
                        if sockets.len() < SOCKET_LIMIT {
                            sockets.push(endpoint);
                        } else {
                            limited = true;
                        }
                    }
                }
                _ => {}
            }
            at += (len + 3) & !3;
        }
    }
}

fn parse_endpoint(payload: &[u8], protocol: u8) -> Result<Endpoint> {
    ensure!(payload.len() >= 72, "short inet_diag message");
    let address = decode_address(payload[0], &payload[8..24])?;
    let remote = decode_address(payload[0], &payload[24..40])?;
    let index = u32::from_ne_bytes(payload[40..44].try_into()?);
    let interface = if index == 0 {
        None
    } else {
        let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
        if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
            None
        } else {
            Some(
                unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    };
    let mut v6_only = None;
    let mut at = 72;
    while at + 4 <= payload.len() {
        let len = u16::from_ne_bytes(payload[at..at + 2].try_into()?) as usize;
        let kind = u16::from_ne_bytes(payload[at + 2..at + 4].try_into()?) & 0x3fff;
        ensure!(
            len >= 4 && at + len <= payload.len(),
            "invalid diagnostic attribute"
        );
        if kind == 11 && len >= 5 {
            v6_only = Some(payload[at + 4] != 0);
        } // INET_DIAG_SKV6ONLY
        at += (len + 3) & !3;
    }
    Ok(Endpoint {
        address,
        remote: (!remote.is_unspecified()).then_some(remote),
        port: u16::from_be_bytes(payload[4..6].try_into()?),
        remote_port: u16::from_be_bytes(payload[6..8].try_into()?),
        protocol,
        interface,
        interface_index: index,
        inode: u32::from_ne_bytes(payload[68..72].try_into()?),
        cookie: u64::from_ne_bytes(payload[44..52].try_into()?),
        v6_only,
        owners: vec![],
    })
}

fn decode_address(family: u8, bytes: &[u8]) -> Result<IpAddr> {
    match family as i32 {
        libc::AF_INET => Ok(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[..4])?).into()),
        libc::AF_INET6 => Ok(Ipv6Addr::from(<[u8; 16]>::try_from(bytes)?).into()),
        _ => bail!("unsupported socket address family"),
    }
}

pub(super) fn local_addresses() -> Vec<IpAddr> {
    let mut list = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return vec![];
    }
    let mut addresses = BTreeSet::new();
    let mut current = list;
    while !current.is_null() && addresses.len() < LOCAL_ADDRESS_LIMIT {
        let interface = unsafe { &*current };
        if !interface.ifa_addr.is_null() {
            match unsafe { (*interface.ifa_addr).sa_family } as i32 {
                libc::AF_INET => {
                    let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in) };
                    addresses.insert(IpAddr::V4(Ipv4Addr::from(
                        address.sin_addr.s_addr.to_ne_bytes(),
                    )));
                }
                libc::AF_INET6 => {
                    let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in6) };
                    addresses.insert(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)));
                }
                _ => {}
            }
        }
        current = interface.ifa_next;
    }
    unsafe {
        libc::freeifaddrs(list);
    }
    addresses.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_ipv6_udp_interface_does_not_abort_following_endpoints() {
        let loopback = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert!(loopback > 0);
        let mut payload = [0u8; 72];
        payload[0] = libc::AF_INET6 as u8;
        payload[68..72].copy_from_slice(&1u32.to_ne_bytes());
        let mut endpoints = vec![];
        // A failed lookup used to return an error here, aborting the UDP dump
        // before any subsequent sockets could be collected.
        for (port, index) in [(57034u16, u32::MAX), (57035, loopback), (57036, 0)] {
            payload[4..6].copy_from_slice(&port.to_be_bytes());
            payload[40..44].copy_from_slice(&index.to_ne_bytes());
            endpoints.push(parse_endpoint(&payload, 17).unwrap());
        }
        assert_eq!(endpoints.len(), 3);
        assert_eq!(endpoints[0].interface_index, u32::MAX);
        assert!(endpoints[0].interface.is_none());
        assert!(!endpoints[0].matches_interface("lo"));
        assert!(!endpoints[0].matches_interface("4294967295"));
        assert_eq!(endpoints[1].interface.as_deref(), Some("lo"));
        assert!(endpoints[1].matches_interface("lo"));
        assert!(!endpoints[1].matches_interface("eth0"));
        assert!(endpoints[2].matches_interface("eth0"));
    }

    #[test]
    fn discovers_real_tcp_and_udp_endpoints() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut sockets = vec![];
        dump(libc::AF_INET as u8, 6, &mut sockets).unwrap();
        dump(libc::AF_INET as u8, 17, &mut sockets).unwrap();
        assert!(
            sockets.iter().any(|s| s.protocol == 6
                && s.port == tcp.local_addr().unwrap().port()
                && s.inode > 0)
        );
        assert!(sockets.iter().any(|s| s.protocol == 17
            && s.port == udp.local_addr().unwrap().port()
            && s.inode > 0));
        assert!(local_addresses().contains(&"127.0.0.1".parse().unwrap()));
    }
}
