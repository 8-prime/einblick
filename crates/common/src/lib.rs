#![no_std]

/// Stable, padding-free map ABI. Addresses are always network-order bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Address {
    pub bytes: [u8; 16],
    pub family: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AssociationKey {
    pub source: Address,
    pub destination: Address,
    pub interface: u32,
    pub protocol: u32,
    pub port: u32,
    pub parsed: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AssociationCounters {
    pub packets: u64,
    pub bytes: u64,
    pub passed: u64,
    pub dropped: u64,
    pub syns: u64,
    pub syn_acks: u64,
    pub resets: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub source_ports: [u16; 8],
    pub source_port_count: u32,
    pub source_ports_truncated: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SourceCounters {
    pub packets: u64,
    pub bytes: u64,
    pub syns: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SynEvent {
    pub address: Address,
    pub port: u16,
    pub reserved: u16,
    pub time_ns: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Deadline {
    pub expires_ns: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Limiter {
    pub second: u64,
    pub count: u64,
}

#[cfg(feature = "userspace")]
mod pod {
    use super::*;
    unsafe impl aya::Pod for Address {}
    unsafe impl aya::Pod for AssociationKey {}
    unsafe impl aya::Pod for AssociationCounters {}
    unsafe impl aya::Pod for SourceCounters {}
    unsafe impl aya::Pod for SynEvent {}
    unsafe impl aya::Pod for Deadline {}
}

pub const TOTAL: u32 = 0;
pub const BYTES: u32 = 1;
pub const PASSED: u32 = 2;
pub const DROPPED: u32 = 3;
pub const PARSE_LIMIT: u32 = 4;
pub const EVENT_LOSS: u32 = 5;
pub const MAP_FULL: u32 = 6;
pub const SOURCE_MISS: u32 = 7;
pub const PORT_MISS: u32 = 8;
pub const ASSOCIATION_MISS: u32 = 9;
pub const METRICS_LEN: u32 = 10;

#[derive(Clone, Copy, Debug, Default)]
pub struct Packet {
    pub source: Address,
    pub destination: Address,
    pub protocol: u8,
    pub port: u16,
    pub source_port: u16,
    pub tcp_flags: u8,
    pub transport_parsed: bool,
    pub syn: bool,
    pub limited: bool,
    pub has_address: bool,
}

/// Packet reads may use slice bounds in userspace or explicit packet-pointer
/// bounds in XDP. The latter must remain visible to the kernel verifier.
pub trait PacketRead {
    fn packet_len(&self) -> usize;
    fn read_byte(&self, at: usize) -> Option<u8>;
}
impl PacketRead for [u8] {
    #[inline(always)]
    fn packet_len(&self) -> usize {
        self.len()
    }
    #[inline(always)]
    fn read_byte(&self, at: usize) -> Option<u8> {
        self.get(at).copied()
    }
}

#[inline(always)]
fn word<R: PacketRead + ?Sized>(data: &R, at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        data.read_byte(at)?,
        data.read_byte(at + 1)?,
    ]))
}

/// Parse only bounded L2/L3/L4 headers. Preserve an extractable source even
/// when fragments or extension headers prevent transport parsing.
#[inline(always)]
pub fn parse(data: &[u8]) -> Packet {
    parse_reader(data)
}

#[inline(always)]
pub fn parse_reader<R: PacketRead + ?Sized>(data: &R) -> Packet {
    let mut p = Packet {
        limited: true,
        ..Packet::default()
    };
    // Indexing a packet slice can leave panic_bounds_check calls in the BPF
    // object even after a preceding length check. Make every read fallible so
    // malformed headers return incomplete evidence without a panic path.
    macro_rules! byte {
        ($offset:expr) => {
            match data.read_byte($offset) {
                Some(value) => value,
                None => return p,
            }
        };
    }
    let Some(mut ether) = word(data, 12) else {
        return p;
    };
    let mut at = 14;
    for _ in 0..2 {
        if ether == 0x8100 || ether == 0x88a8 {
            let Some(next) = word(data, at + 2) else {
                return p;
            };
            ether = next;
            at += 4;
        }
    }
    let end;
    if ether == 0x0800 {
        if data.packet_len() < at + 20 || byte!(at) >> 4 != 4 {
            return p;
        }
        p.source.family = 4;
        p.destination.family = 4;
        for i in 0..4 {
            p.source.bytes[i] = byte!(at + 12 + i);
            p.destination.bytes[i] = byte!(at + 16 + i);
        }
        p.has_address = true;
        p.protocol = byte!(at + 9);
        let ihl = (byte!(at) as usize & 15) * 4;
        let size = word(data, at + 2).unwrap_or(0) as usize;
        if ihl < 20 || size < ihl || data.packet_len() < at + size {
            return p;
        }
        end = at + size;
        // All fragmented packets are counted without interpreting fragment payload.
        if word(data, at + 6).unwrap_or(0) & 0x3fff != 0 {
            return p;
        }
        at += ihl;
    } else if ether == 0x86dd {
        if data.packet_len() < at + 40 || byte!(at) >> 4 != 6 {
            return p;
        }
        p.source.family = 6;
        p.destination.family = 6;
        for i in 0..16 {
            p.source.bytes[i] = byte!(at + 8 + i);
            p.destination.bytes[i] = byte!(at + 24 + i);
        }
        p.has_address = true;
        p.protocol = byte!(at + 6);
        let size = word(data, at + 4).unwrap_or(0) as usize;
        if size == 0 || data.packet_len() < at + 40 + size {
            return p;
        }
        end = at + 40 + size;
        at += 40;
        for _ in 0..4 {
            if p.protocol == 44 {
                return p;
            }
            if p.protocol == 0 || p.protocol == 43 || p.protocol == 60 || p.protocol == 51 {
                if at + 2 > end {
                    return p;
                }
                let next = byte!(at);
                let size = if p.protocol == 51 {
                    (byte!(at + 1) as usize + 2) * 4
                } else {
                    (byte!(at + 1) as usize + 1) * 8
                };
                if at + size > end {
                    return p;
                }
                at += size;
                p.protocol = next;
            }
        }
        if matches!(p.protocol, 0 | 43 | 44 | 60 | 51 | 50) {
            return p;
        }
    } else {
        return p;
    }
    if p.protocol == 6 {
        if at + 20 > end {
            return p;
        }
        let size = (byte!(at + 12) >> 4) as usize * 4;
        if size < 20 || at + size > end {
            return p;
        }
        p.port = word(data, at + 2).unwrap_or(0);
        p.source_port = word(data, at).unwrap_or(0);
        p.tcp_flags = byte!(at + 13);
        p.syn = p.tcp_flags & 0x12 == 0x02;
        p.transport_parsed = true;
    } else if p.protocol == 17 {
        if at + 8 > end {
            return p;
        }
        let size = word(data, at + 4).unwrap_or(0) as usize;
        if size < 8 || at + size > end {
            return p;
        }
        p.port = word(data, at + 2).unwrap_or(0);
        p.source_port = word(data, at).unwrap_or(0);
        p.transport_parsed = true;
    }
    p.limited = false;
    p
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    fn ipv4() -> std::vec::Vec<u8> {
        let mut b = std::vec![0; 54];
        b[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        b[14] = 0x45;
        b[16..18].copy_from_slice(&40u16.to_be_bytes());
        b[23] = 6;
        b[26..30].copy_from_slice(&[192, 0, 2, 1]);
        b[36..38].copy_from_slice(&443u16.to_be_bytes());
        b[46] = 0x50;
        b[47] = 2;
        b
    }
    #[test]
    fn syn_and_ack() {
        let mut b = ipv4();
        let p = parse(&b);
        assert!(p.syn && !p.limited);
        assert_eq!(p.port, 443);
        assert_eq!(&p.source.bytes[..4], &[192, 0, 2, 1]);
        b[47] = 0x12;
        assert!(!parse(&b).syn);
    }
    #[test]
    fn association_addresses_ports_and_tcp_flags() {
        let mut b = ipv4();
        b[30..34].copy_from_slice(&[192, 0, 2, 44]);
        b[34..36].copy_from_slice(&52000u16.to_be_bytes());
        let p = parse(&b);
        assert_eq!(&p.destination.bytes[..4], &[192, 0, 2, 44]);
        assert_eq!(p.source_port, 52000);
        assert!(p.transport_parsed && p.syn);
        b[47] = 0x14;
        assert_eq!(parse(&b).tcp_flags, 0x14);
        b[20] = 0x20;
        let fragment = parse(&b);
        assert!(!fragment.transport_parsed);
        assert_eq!(fragment.destination.family, 4);
    }
    #[test]
    fn udp_zero_port_is_distinct_from_unparsed_transport() {
        let mut b = ipv4();
        b[23] = 17;
        b[34..36].copy_from_slice(&53u16.to_be_bytes());
        b[36..38].copy_from_slice(&0u16.to_be_bytes());
        b[38..40].copy_from_slice(&20u16.to_be_bytes());
        let p = parse(&b);
        assert!(p.transport_parsed && !p.syn);
        assert_eq!(p.source_port, 53);
        assert_eq!(p.port, 0);
        b[38..40].copy_from_slice(&100u16.to_be_bytes());
        assert!(!parse(&b).transport_parsed);
    }
    #[test]
    fn truncation_and_fragment_preserve_source() {
        let mut b = ipv4();
        b[20] = 0x20;
        let p = parse(&b);
        assert!(p.has_address && p.limited && !p.syn);
        for n in 0..b.len() {
            let _ = parse(&b[..n]);
        }
    }
    #[test]
    fn double_vlan() {
        let b = ipv4();
        let mut v = std::vec::Vec::from(&b[..12]);
        v.extend_from_slice(&[0x88, 0xa8, 0, 1, 0x81, 0, 0, 2, 8, 0]);
        v.extend_from_slice(&b[14..]);
        assert_eq!(parse(&v).port, 443);
    }
    #[test]
    fn ipv6_extension_and_fragment() {
        let mut b = std::vec![0;82];
        b[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        b[14] = 0x60;
        b[18..20].copy_from_slice(&28u16.to_be_bytes());
        b[20] = 0;
        b[22..38].copy_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        b[54] = 6;
        b[64..66].copy_from_slice(&22u16.to_be_bytes());
        b[74] = 0x50;
        b[75] = 2;
        assert!(parse(&b).syn);
        assert_eq!(parse(&b).source.family, 6);
        b[20] = 44;
        assert!(parse(&b).limited && parse(&b).has_address);
    }
    #[test]
    fn malformed_ipv6_extension_lengths_and_truncation() {
        let mut b = std::vec![0; 82];
        b[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        b[14] = 0x60;
        b[18..20].copy_from_slice(&28u16.to_be_bytes());
        b[20] = 0;
        b[54] = 6;
        b[74] = 0x50;
        b[75] = 2;
        assert!(parse(&b).syn);
        for n in 0..b.len() {
            let p = parse(&b[..n]);
            assert!(p.limited && !p.syn, "truncated at {n}");
        }
        for length in 1..=255 {
            b[55] = length;
            let p = parse(&b);
            assert!(p.has_address && p.limited && !p.syn);
        }
    }
}
