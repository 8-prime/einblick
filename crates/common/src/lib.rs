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
pub const METRICS_LEN: u32 = 7;

#[derive(Clone, Copy, Debug, Default)]
pub struct Packet {
    pub source: Address,
    pub protocol: u8,
    pub port: u16,
    pub syn: bool,
    pub limited: bool,
    pub has_address: bool,
}

#[inline(always)]
fn word(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]))
}

/// Parse only bounded L2/L3/L4 headers. Preserve an extractable source even
/// when fragments or extension headers prevent transport parsing.
#[inline(always)]
pub fn parse(data: &[u8]) -> Packet {
    let mut p = Packet {
        limited: true,
        ..Packet::default()
    };
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
        if data.len() < at + 20 || data[at] >> 4 != 4 {
            return p;
        }
        p.source.family = 4;
        for i in 0..4 {
            p.source.bytes[i] = data[at + 12 + i];
        }
        p.has_address = true;
        p.protocol = data[at + 9];
        let ihl = (data[at] as usize & 15) * 4;
        let size = word(data, at + 2).unwrap_or(0) as usize;
        if ihl < 20 || size < ihl || data.len() < at + size {
            return p;
        }
        end = at + size;
        // All fragmented packets are counted without interpreting fragment payload.
        if word(data, at + 6).unwrap_or(0) & 0x3fff != 0 {
            return p;
        }
        at += ihl;
    } else if ether == 0x86dd {
        if data.len() < at + 40 || data[at] >> 4 != 6 {
            return p;
        }
        p.source.family = 6;
        for i in 0..16 {
            p.source.bytes[i] = data[at + 8 + i];
        }
        p.has_address = true;
        p.protocol = data[at + 6];
        let size = word(data, at + 4).unwrap_or(0) as usize;
        if size == 0 || data.len() < at + 40 + size {
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
                let next = data[at];
                let size = if p.protocol == 51 {
                    (data[at + 1] as usize + 2) * 4
                } else {
                    (data[at + 1] as usize + 1) * 8
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
        let size = (data[at + 12] >> 4) as usize * 4;
        if size < 20 || at + size > end {
            return p;
        }
        p.port = word(data, at + 2).unwrap_or(0);
        p.syn = data[at + 13] & 0x12 == 0x02;
    } else if p.protocol == 17 {
        if at + 8 > end {
            return p;
        }
        let size = word(data, at + 4).unwrap_or(0) as usize;
        if size < 8 || at + size > end {
            return p;
        }
        p.port = word(data, at + 2).unwrap_or(0);
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
}
