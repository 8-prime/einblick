//! Read-only, bounded NETLINK_NETFILTER dumps. Match both directions of a NAT
//! connection to Docker addresses, without guessing process or tunnel ownership.
use super::{ContainerAddress, NatEndpoint, SOCKET_LIMIT};
use anyhow::{Result, bail, ensure};
use einblick_core::{ApplicationEvidence, unix_now};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

const CT_NEW: u16 = 0x100; // NFNL_SUBSYS_CTNETLINK / IPCTNL_MSG_CT_NEW
const CT_GET: u16 = 0x101;
const FLOW_SCAN_LIMIT: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Tuple {
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    protocol: u8,
}

struct Flow {
    original: Tuple,
    reply: Tuple,
}

type Addresses<'a> = BTreeMap<IpAddr, Vec<&'a ApplicationEvidence>>;

pub(super) fn discover(containers: &[ContainerAddress]) -> Result<(Vec<NatEndpoint>, bool)> {
    if containers.is_empty() {
        return Ok((vec![], false));
    }
    let mut addresses = Addresses::new();
    for container in containers {
        addresses
            .entry(container.address)
            .or_default()
            .push(&container.application);
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        )
    };
    ensure!(
        raw >= 0,
        "open conntrack diagnostics: {}",
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
        "set conntrack diagnostic timeout"
    );
    let mut destination: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    destination.nl_family = libc::AF_NETLINK as u16;
    let mut request = [0u8; 20]; // nlmsghdr + nfgenmsg, AF_UNSPEC dumps both families
    request[..4].copy_from_slice(&20u32.to_ne_bytes());
    request[4..6].copy_from_slice(&CT_GET.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
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
        "request conntrack diagnostics: {}",
        std::io::Error::last_os_error()
    );

    let started = Instant::now();
    let mut buffer = [0u8; 65536];
    let mut mappings = vec![];
    let mut scanned = 0;
    loop {
        ensure!(
            started.elapsed() < Duration::from_secs(1),
            "conntrack dump timed out"
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
            "receive conntrack diagnostics: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            size as usize <= buffer.len() && source.nl_pid == 0,
            "invalid conntrack sender or truncated datagram"
        );
        let mut messages = &buffer[..size as usize];
        while !messages.is_empty() {
            ensure!(messages.len() >= 16, "short conntrack netlink header");
            let len = u32::from_ne_bytes(messages[..4].try_into()?) as usize;
            ensure!(
                len >= 16 && len <= messages.len(),
                "invalid conntrack netlink length"
            );
            let kind = u16::from_ne_bytes(messages[4..6].try_into()?);
            let flags = u16::from_ne_bytes(messages[6..8].try_into()?);
            ensure!(flags & 0x10 == 0, "interrupted conntrack dump");
            ensure!(
                u32::from_ne_bytes(messages[8..12].try_into()?) == 1,
                "unexpected conntrack diagnostic sequence"
            );
            let payload = &messages[16..len];
            match kind {
                3 => {
                    if payload.len() >= 4 {
                        kernel_error(payload)?;
                    }
                    return Ok((mappings, false));
                }
                2 => kernel_error(payload)?,
                CT_NEW => {
                    scanned += 1;
                    if scanned > FLOW_SCAN_LIMIT {
                        return Ok((mappings, true));
                    }
                    if let Some(flow) = parse_flow(payload)?
                        && append_mappings(&flow, &addresses, unix_now(), &mut mappings)
                    {
                        return Ok((mappings, true));
                    }
                }
                _ => {}
            }
            let aligned = (len + 3) & !3;
            ensure!(aligned <= messages.len(), "short conntrack netlink padding");
            messages = &messages[aligned..];
        }
    }
}

fn kernel_error(payload: &[u8]) -> Result<()> {
    ensure!(payload.len() >= 4, "short conntrack kernel error");
    let code = i32::from_ne_bytes(payload[..4].try_into()?);
    if code != 0 {
        bail!(
            "conntrack kernel error: {}",
            std::io::Error::from_raw_os_error(code.saturating_neg())
        );
    }
    Ok(())
}

fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut attrs = vec![];
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 4, "short conntrack attribute header");
        let len = u16::from_ne_bytes(bytes[..2].try_into()?) as usize;
        let kind = u16::from_ne_bytes(bytes[2..4].try_into()?) & 0x3fff;
        ensure!(
            len >= 4 && len <= bytes.len(),
            "invalid conntrack attribute length"
        );
        attrs.push((kind, &bytes[4..len]));
        let aligned = (len + 3) & !3;
        if len == bytes.len() {
            break;
        }
        ensure!(aligned <= bytes.len(), "short conntrack attribute padding");
        bytes = &bytes[aligned..];
    }
    Ok(attrs)
}

fn attribute<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Result<Option<&'a [u8]>> {
    let mut matching = attrs.iter().filter(|a| a.0 == kind);
    let value = matching.next().map(|a| a.1);
    ensure!(matching.next().is_none(), "duplicate conntrack attribute");
    Ok(value)
}

fn required<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Result<&'a [u8]> {
    attribute(attrs, kind)?.ok_or_else(|| anyhow::anyhow!("missing conntrack attribute {kind}"))
}

fn default_zone(attrs: &[(u16, &[u8])], kind: u16) -> Result<bool> {
    let Some(zone) = attribute(attrs, kind)? else {
        return Ok(true);
    };
    Ok(u16::from_be_bytes(zone.try_into()?) == 0)
}

fn parse_flow(payload: &[u8]) -> Result<Option<Flow>> {
    ensure!(payload.len() >= 4, "short conntrack nfgenmsg");
    let family = payload[0] as i32;
    if !matches!(family, libc::AF_INET | libc::AF_INET6) {
        return Ok(None);
    }
    ensure!(payload[1] == 0, "unknown conntrack nfnetlink version");
    let attrs = attributes(&payload[4..])?;
    // The packet capture has no conntrack zone identity. Never combine tuples
    // from custom zones with otherwise identical flows in the default zone.
    if !default_zone(&attrs, 18)? {
        // CTA_ZONE
        return Ok(None);
    }
    let Some(original) = parse_tuple(required(&attrs, 1)?, family)? else {
        return Ok(None);
    };
    let Some(reply) = parse_tuple(required(&attrs, 2)?, family)? else {
        return Ok(None);
    };
    ensure!(
        original.protocol == reply.protocol,
        "conntrack tuple protocol mismatch"
    );
    Ok(Some(Flow { original, reply }))
}

fn parse_tuple(bytes: &[u8], family: i32) -> Result<Option<Tuple>> {
    let attrs = attributes(bytes)?;
    if !default_zone(&attrs, 3)? {
        // CTA_TUPLE_ZONE
        return Ok(None);
    }
    let proto = attributes(required(&attrs, 2)?)?;
    let protocol = <[u8; 1]>::try_from(required(&proto, 1)?)?[0];
    if !matches!(protocol, 6 | 17) {
        return Ok(None);
    }
    let ip = attributes(required(&attrs, 1)?)?;
    let address = |v4, v6| -> Result<IpAddr> {
        Ok(if family == libc::AF_INET {
            Ipv4Addr::from(<[u8; 4]>::try_from(required(&ip, v4)?)?).into()
        } else {
            Ipv6Addr::from(<[u8; 16]>::try_from(required(&ip, v6)?)?).into()
        })
    };
    let tuple = Tuple {
        source: address(1, 3)?,
        destination: address(2, 4)?,
        source_port: u16::from_be_bytes(required(&proto, 2)?.try_into()?),
        destination_port: u16::from_be_bytes(required(&proto, 3)?.try_into()?),
        protocol,
    };
    if tuple.source_port == 0 || tuple.destination_port == 0 {
        return Ok(None);
    }
    Ok(Some(tuple))
}

/// Return true if the mapping limit was reached. Address identity is only
/// container evidence; it deliberately doesn't claim a process or WireGuard peer.
fn append_mappings(
    flow: &Flow,
    addresses: &Addresses<'_>,
    observed: i64,
    out: &mut Vec<NatEndpoint>,
) -> bool {
    for (packet, target, target_port) in [
        (&flow.original, flow.reply.source, flow.reply.source_port),
        (&flow.reply, flow.original.source, flow.original.source_port),
    ] {
        if packet.destination == target && packet.destination_port == target_port {
            continue; // No destination translation in this direction.
        }
        for owner in addresses.get(&target).into_iter().flatten() {
            if out.len() == SOCKET_LIMIT {
                return true;
            }
            let mut application = (*owner).clone();
            application.observed_from = observed.max(application.observed_from);
            application.observed_to = application.observed_from;
            out.push(NatEndpoint {
                source: packet.source,
                destination: packet.destination,
                source_port: packet.source_port,
                port: packet.destination_port,
                protocol: packet.protocol,
                application,
            });
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use einblick_core::ApplicationMethod;

    fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        out.extend_from_slice(&((payload.len() + 4) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize((out.len() + 3) & !3, 0);
        out
    }

    fn tuple(
        source: &str,
        source_port: u16,
        destination: &str,
        destination_port: u16,
        protocol: u8,
    ) -> Vec<u8> {
        let source: IpAddr = source.parse().unwrap();
        let destination: IpAddr = destination.parse().unwrap();
        let mut ip = vec![];
        match (source, destination) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                ip.extend(attr(1, &s.octets()));
                ip.extend(attr(2, &d.octets()));
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                ip.extend(attr(3, &s.octets()));
                ip.extend(attr(4, &d.octets()));
            }
            _ => panic!("mixed families"),
        }
        let mut proto = attr(1, &[protocol]);
        proto.extend(attr(2, &source_port.to_be_bytes()));
        proto.extend(attr(3, &destination_port.to_be_bytes()));
        let mut out = attr(0x8001, &ip);
        out.extend(attr(0x8002, &proto));
        out
    }

    fn flow(family: u8, original: Vec<u8>, reply: Vec<u8>) -> Vec<u8> {
        let mut out = vec![family, 0, 0, 0];
        out.extend(attr(0x8001, &original));
        out.extend(attr(0x8002, &reply));
        out
    }

    #[test]
    fn parses_the_gluetun_reply_and_maps_container_without_a_process_owner() {
        let data = flow(
            libc::AF_INET as u8,
            tuple("172.30.0.2", 57034, "152.233.20.208", 1194, 17),
            tuple("152.233.20.208", 1194, "192.168.2.30", 57034, 17),
        );
        let parsed = parse_flow(&data).unwrap().unwrap();
        assert_eq!(parsed.reply.source_port, 1194);
        assert_eq!(parsed.original.protocol, 17);
        let evidence = ApplicationEvidence {
            id: format!("docker:{}", "a".repeat(64)),
            name: "arr-stack-gluetun-1".into(),
            method: ApplicationMethod::NatContainer,
            pid: None,
            process_start: None,
            executable: None,
            service: Some("gluetun".into()),
            container_id: Some("a".repeat(64)),
            observed_from: 100,
            observed_to: 100,
        };
        let addresses = BTreeMap::from([("172.30.0.2".parse().unwrap(), vec![&evidence])]);
        let mut mappings = vec![];
        assert!(!append_mappings(&parsed, &addresses, 101, &mut mappings));
        assert_eq!(mappings.len(), 1);
        let mapping = &mappings[0];
        assert_eq!(
            mapping.destination,
            "192.168.2.30".parse::<IpAddr>().unwrap()
        );
        assert_eq!(mapping.port, 57034);
        assert_eq!(mapping.source, "152.233.20.208".parse::<IpAddr>().unwrap());
        assert_eq!(mapping.application.name, "arr-stack-gluetun-1");
        assert!(mapping.application.pid.is_none());
        assert_eq!(mapping.application.observed_from, 101);
        assert_eq!(mapping.application.observed_to, 101);
    }

    #[test]
    fn parses_ipv6_tcp_dnat_and_distinguishes_the_translated_port() {
        let data = flow(
            libc::AF_INET6 as u8,
            tuple("2001:db8::1", 42000, "2001:db8::2", 8443, 6),
            tuple("fd00::2", 443, "2001:db8::1", 42000, 6),
        );
        let parsed = parse_flow(&data).unwrap().unwrap();
        assert_eq!(parsed.original.destination_port, 8443);
        assert_eq!(parsed.reply.source_port, 443);
        assert_eq!(parsed.reply.source, "fd00::2".parse::<IpAddr>().unwrap());
        let application = ApplicationEvidence {
            id: format!("docker:{}", "c".repeat(64)),
            name: "web".into(),
            method: ApplicationMethod::NatContainer,
            pid: None,
            process_start: None,
            executable: None,
            service: None,
            container_id: Some("c".repeat(64)),
            observed_from: 100,
            observed_to: 100,
        };
        let addresses = BTreeMap::from([("fd00::2".parse().unwrap(), vec![&application])]);
        let mut out = vec![];
        assert!(!append_mappings(&parsed, &addresses, 100, &mut out));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(out[0].destination, "2001:db8::2".parse::<IpAddr>().unwrap());
        assert_eq!(out[0].source_port, 42000);
        assert_eq!(out[0].port, 8443);
        assert_eq!(out[0].protocol, 6);
        assert_eq!(out[0].application.name, "web");
    }

    #[test]
    fn rejects_malformed_truncated_duplicate_and_nondefault_zone_messages() {
        let data = flow(
            libc::AF_INET as u8,
            tuple("172.30.0.2", 57034, "152.233.20.208", 1194, 17),
            tuple("152.233.20.208", 1194, "192.168.2.30", 57034, 17),
        );
        for length in 0..data.len() {
            if let Ok(Some(_)) = parse_flow(&data[..length]) {
                panic!("accepted truncation at {length}");
            }
        }
        let mut zoned = data.clone();
        zoned.extend(attr(18, &1u16.to_be_bytes()));
        assert!(parse_flow(&zoned).unwrap().is_none());
        let mut duplicated = data.clone();
        duplicated.extend(attr(
            1,
            &tuple("172.30.0.3", 57034, "152.233.20.208", 1194, 17),
        ));
        assert!(parse_flow(&duplicated).is_err());
        assert!(attributes(&[0, 0, 1, 0]).is_err());
    }

    #[test]
    fn no_mapping_is_created_for_untranslated_or_unknown_container_flows() {
        let data = flow(
            libc::AF_INET as u8,
            tuple("172.30.0.2", 57034, "152.233.20.208", 1194, 17),
            tuple("152.233.20.208", 1194, "172.30.0.2", 57034, 17),
        );
        let parsed = parse_flow(&data).unwrap().unwrap();
        let mut out = vec![];
        assert!(!append_mappings(&parsed, &BTreeMap::new(), 100, &mut out));
        assert!(out.is_empty());
    }

    #[test]
    #[ignore = "requires root, iptables and an isolated network namespace; run scripts/test-kernel.sh"]
    fn real_kernel_snat_reply_maps_to_container_with_changed_host_port() {
        use std::{net::UdpSocket, process::Command};
        assert_eq!(unsafe { libc::geteuid() }, 0, "requires root");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "refusing to change the host network namespace"
        );
        let run = |program: &str, args: &[&str]| {
            let output = Command::new(program).args(args).output().unwrap();
            assert!(
                output.status.success(),
                "{program}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run("ip", &["link", "set", "lo", "up"]);
        for address in ["172.30.0.2/32", "192.0.2.30/32", "198.51.100.1/32"] {
            run("ip", &["address", "add", address, "dev", "lo"]);
        }
        run(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "172.30.0.2",
                "-d",
                "198.51.100.1",
                "-p",
                "udp",
                "--sport",
                "57034",
                "--dport",
                "1194",
                "-j",
                "SNAT",
                "--to-source",
                "192.0.2.30:57035",
            ],
        );
        let client = UdpSocket::bind("172.30.0.2:57034").unwrap();
        let server = UdpSocket::bind("198.51.100.1:1194").unwrap();
        for socket in [&client, &server] {
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        client
            .send_to(b"request", server.local_addr().unwrap())
            .unwrap();
        let mut buffer = [0; 32];
        let (_, translated) = server.recv_from(&mut buffer).unwrap();
        assert_eq!(translated.to_string(), "192.0.2.30:57035");
        server.send_to(b"reply", translated).unwrap();
        client.recv_from(&mut buffer).unwrap();
        let evidence = ApplicationEvidence {
            id: format!("docker:{}", "a".repeat(64)),
            name: "kernel-nat-test".into(),
            method: ApplicationMethod::NatContainer,
            pid: None,
            process_start: None,
            executable: None,
            service: None,
            container_id: Some("a".repeat(64)),
            observed_from: unix_now(),
            observed_to: unix_now(),
        };
        let (mappings, limited) = discover(&[ContainerAddress {
            address: "172.30.0.2".parse().unwrap(),
            application: evidence,
        }])
        .unwrap();
        assert!(!limited);
        let mapping = mappings
            .iter()
            .find(|m| {
                m.destination == "192.0.2.30".parse::<IpAddr>().unwrap()
                    && m.port == 57035
                    && m.source == "198.51.100.1".parse::<IpAddr>().unwrap()
                    && m.source_port == 1194
                    && m.protocol == 17
            })
            .expect("kernel SNAT reply missing");
        assert_eq!(mapping.application.name, "kernel-nat-test");
        assert_eq!(mapping.application.method, ApplicationMethod::NatContainer);
        assert!(mapping.application.pid.is_none());
    }
}
