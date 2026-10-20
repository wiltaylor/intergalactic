//! Minimal IPv4/IPv6 header parsing. We only need addresses, protocol and ports.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    /// Source port, or ICMP identifier for echo request/reply.
    pub sport: u16,
    /// Destination port, or ICMP type for ICMP/ICMPv6.
    pub dport: u16,
    pub tcp_flags: u8,
    /// Offset of the transport header inside the packet.
    pub l4_offset: usize,
}

pub fn version(pkt: &[u8]) -> Option<u8> {
    pkt.first().map(|b| b >> 4)
}

pub fn dst(pkt: &[u8]) -> Option<IpAddr> {
    match version(pkt)? {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            pkt[16], pkt[17], pkt[18], pkt[19],
        ))),
        6 if pkt.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&pkt[24..40]).ok()?,
        ))),
        _ => None,
    }
}

pub fn src(pkt: &[u8]) -> Option<IpAddr> {
    match version(pkt)? {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            pkt[12], pkt[13], pkt[14], pkt[15],
        ))),
        6 if pkt.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&pkt[8..24]).ok()?,
        ))),
        _ => None,
    }
}

pub fn parse_flow(pkt: &[u8]) -> Option<Flow> {
    let (src, dst, proto, l4_offset, fragment) = match version(pkt)? {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return None;
            }
            let frag_offset = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
            (src(pkt)?, dst(pkt)?, pkt[9], ihl, frag_offset != 0)
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            // Walk extension headers to the transport header.
            let mut next = pkt[6];
            let mut off = 40usize;
            let mut fragment = false;
            loop {
                match next {
                    0 | 43 | 60 | 135 | 139 | 140 => {
                        if pkt.len() < off + 8 {
                            return None;
                        }
                        let len = (pkt[off + 1] as usize + 1) * 8;
                        next = pkt[off];
                        off += len;
                    }
                    44 => {
                        if pkt.len() < off + 8 {
                            return None;
                        }
                        let frag_off = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) >> 3;
                        fragment = frag_off != 0;
                        next = pkt[off];
                        off += 8;
                    }
                    _ => break,
                }
                if off > pkt.len() {
                    return None;
                }
            }
            (src(pkt)?, dst(pkt)?, next, off, fragment)
        }
        _ => return None,
    };
    let l4 = pkt.get(l4_offset..)?;
    let base = Flow {
        src,
        dst,
        proto,
        sport: 0,
        dport: 0,
        tcp_flags: 0,
        l4_offset,
    };
    if fragment {
        return Some(base);
    }
    match proto {
        PROTO_TCP => {
            if l4.len() < 14 {
                return None;
            }
            Some(Flow {
                sport: u16::from_be_bytes([l4[0], l4[1]]),
                dport: u16::from_be_bytes([l4[2], l4[3]]),
                tcp_flags: l4[13],
                ..base
            })
        }
        PROTO_UDP => {
            if l4.len() < 4 {
                return None;
            }
            Some(Flow {
                sport: u16::from_be_bytes([l4[0], l4[1]]),
                dport: u16::from_be_bytes([l4[2], l4[3]]),
                ..base
            })
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            if l4.len() < 4 {
                return None;
            }
            let icmp_type = l4[0];
            let is_echo = matches!(
                (proto, icmp_type),
                (PROTO_ICMP, 0 | 8) | (PROTO_ICMPV6, 128 | 129)
            );
            let id = if is_echo && l4.len() >= 8 {
                u16::from_be_bytes([l4[4], l4[5]])
            } else {
                0
            };
            Some(Flow {
                sport: id,
                dport: icmp_type as u16,
                ..base
            })
        }
        _ => Some(base),
    }
}

// ---- builders (tests, DNS replies) ------------------------------------------

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn sum_bytes(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

/// Build an IP packet (v4 or v6 depending on the addresses). Both addresses must
/// be the same family. For UDP the checksum is filled in (mandatory on IPv6).
pub fn build_ip(src: IpAddr, dst: IpAddr, proto: u8, payload: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => build_ipv4(s, d, proto, payload),
        (IpAddr::V6(s), IpAddr::V6(d)) => build_ipv6(s, d, proto, payload),
        _ => Vec::new(),
    }
}

pub fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6] = 0x40; // DF
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let csum = fold(sum_bytes(&p[..20]));
    p[10..12].copy_from_slice(&csum.to_be_bytes());
    p[20..].copy_from_slice(payload);
    if proto == PROTO_UDP && payload.len() >= 8 {
        let c = l4_checksum(IpAddr::V4(src), IpAddr::V4(dst), proto, &p[20..]);
        p[26..28].copy_from_slice(&c.to_be_bytes());
    } else if proto == PROTO_TCP && payload.len() >= 20 {
        let c = l4_checksum(IpAddr::V4(src), IpAddr::V4(dst), proto, &p[20..]);
        p[36..38].copy_from_slice(&c.to_be_bytes());
    }
    p
}

pub fn build_ipv6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40 + payload.len()];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    p[6] = proto;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40..].copy_from_slice(payload);
    let csum_off = match proto {
        PROTO_UDP if payload.len() >= 8 => Some(46),
        PROTO_TCP if payload.len() >= 20 => Some(56),
        PROTO_ICMPV6 if payload.len() >= 4 => Some(42),
        _ => None,
    };
    if let Some(off) = csum_off {
        let c = l4_checksum(IpAddr::V6(src), IpAddr::V6(dst), proto, &p[40..]);
        p[off..off + 2].copy_from_slice(&c.to_be_bytes());
    }
    p
}

/// Transport checksum over the pseudo-header and the L4 segment (checksum
/// field assumed zero in `l4`). Returns 0xffff instead of 0 for UDP.
pub fn l4_checksum(src: IpAddr, dst: IpAddr, proto: u8, l4: &[u8]) -> u16 {
    let mut sum = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum += sum_bytes(&s.octets()) + sum_bytes(&d.octets());
            sum += proto as u32;
            sum += l4.len() as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            sum += sum_bytes(&s.octets()) + sum_bytes(&d.octets());
            sum += l4.len() as u32;
            sum += proto as u32;
        }
        _ => return 0,
    }
    sum += sum_bytes(l4);
    let c = fold(sum);
    if c == 0 && proto == PROTO_UDP {
        0xffff
    } else {
        c
    }
}

/// UDP datagram inside an IP packet of the right family.
pub fn build_udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut l4 = Vec::with_capacity(8 + data.len());
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    l4.extend_from_slice(data);
    build_ip(src, dst, PROTO_UDP, &l4)
}

/// TCP segment helper for tests: 20-byte header with the given flags.
pub fn build_tcp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, flags: u8) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&sport.to_be_bytes());
    l4[2..4].copy_from_slice(&dport.to_be_bytes());
    l4[12] = 0x50;
    l4[13] = flags;
    build_ip(src, dst, PROTO_TCP, &l4)
}

/// ICMP / ICMPv6 echo helper for tests.
pub fn build_icmp_echo(src: IpAddr, dst: IpAddr, reply: bool, id: u16) -> Vec<u8> {
    let mut l4 = vec![0u8; 8];
    let v6 = src.is_ipv6();
    l4[0] = match (v6, reply) {
        (false, false) => 8,
        (false, true) => 0,
        (true, false) => 128,
        (true, true) => 129,
    };
    l4[4..6].copy_from_slice(&id.to_be_bytes());
    build_ip(src, dst, if v6 { PROTO_ICMPV6 } else { PROTO_ICMP }, &l4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_udp_and_tcp_v4() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
        let udp = build_udp(a, 5000, b, 53, b"hi");
        let f = parse_flow(&udp).unwrap();
        assert_eq!(
            (f.src, f.dst, f.proto, f.sport, f.dport),
            (a, b, PROTO_UDP, 5000, 53)
        );
        assert_eq!(dst(&udp), Some(b));
        let tcp = build_tcp(a, 40000, b, 22, TCP_SYN);
        let f = parse_flow(&tcp).unwrap();
        assert_eq!(f.dport, 22);
        assert_eq!(f.tcp_flags, TCP_SYN);
        assert!(parse_flow(&[0x50, 0, 0, 0]).is_none());
    }

    #[test]
    fn parses_v6_and_checksums_udp() {
        let a: IpAddr = "fd00::1".parse().unwrap();
        let b: IpAddr = "fd00::2".parse().unwrap();
        let udp = build_udp(a, 1234, b, 53, b"query");
        assert_eq!(udp.len(), 40 + 8 + 5);
        let f = parse_flow(&udp).unwrap();
        assert_eq!(
            (f.src, f.dst, f.proto, f.sport, f.dport, f.l4_offset),
            (a, b, PROTO_UDP, 1234, 53, 40)
        );
        // Verify the checksum: recomputing over the segment with the stored
        // checksum included must yield zero (or 0xffff after folding).
        let mut l4 = udp[40..].to_vec();
        let stored = u16::from_be_bytes([l4[6], l4[7]]);
        l4[6] = 0;
        l4[7] = 0;
        assert_eq!(l4_checksum(a, b, PROTO_UDP, &l4), stored);
        let echo = build_icmp_echo(a, b, false, 9);
        let f = parse_flow(&echo).unwrap();
        assert_eq!((f.proto, f.dport, f.sport), (PROTO_ICMPV6, 128, 9));
    }
}
