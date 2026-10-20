//! Minimal IPv4 header parsing. We only need addresses, protocol and ports.

use std::net::Ipv4Addr;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    /// Source port, or ICMP identifier for echo request/reply.
    pub sport: u16,
    /// Destination port, or ICMP type for ICMP.
    pub dport: u16,
    pub tcp_flags: u8,
}

pub fn version(pkt: &[u8]) -> Option<u8> {
    pkt.first().map(|b| b >> 4)
}

pub fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || version(pkt)? != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

pub fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || version(pkt)? != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

pub fn parse_flow(pkt: &[u8]) -> Option<Flow> {
    if pkt.len() < 20 || version(pkt)? != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let proto = pkt[9];
    let src = ipv4_src(pkt)?;
    let dst = ipv4_dst(pkt)?;
    let frag_offset = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
    let l4 = &pkt[ihl..];
    // Non-first fragments carry no transport header; treat as ports 0.
    if frag_offset != 0 {
        return Some(Flow {
            src,
            dst,
            proto,
            sport: 0,
            dport: 0,
            tcp_flags: 0,
        });
    }
    match proto {
        PROTO_TCP => {
            if l4.len() < 14 {
                return None;
            }
            Some(Flow {
                src,
                dst,
                proto,
                sport: u16::from_be_bytes([l4[0], l4[1]]),
                dport: u16::from_be_bytes([l4[2], l4[3]]),
                tcp_flags: l4[13],
            })
        }
        PROTO_UDP => {
            if l4.len() < 4 {
                return None;
            }
            Some(Flow {
                src,
                dst,
                proto,
                sport: u16::from_be_bytes([l4[0], l4[1]]),
                dport: u16::from_be_bytes([l4[2], l4[3]]),
                tcp_flags: 0,
            })
        }
        PROTO_ICMP => {
            if l4.len() < 4 {
                return None;
            }
            let icmp_type = l4[0];
            let id = if l4.len() >= 8 && (icmp_type == 0 || icmp_type == 8) {
                u16::from_be_bytes([l4[4], l4[5]])
            } else {
                0
            };
            Some(Flow {
                src,
                dst,
                proto,
                sport: id,
                dport: icmp_type as u16,
                tcp_flags: 0,
            })
        }
        _ => Some(Flow {
            src,
            dst,
            proto,
            sport: 0,
            dport: 0,
            tcp_flags: 0,
        }),
    }
}

/// Build a minimal IPv4 packet (for tests and probes). Checksum is computed.
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
    let mut sum = 0u32;
    for i in (0..20).step_by(2) {
        sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p[20..].copy_from_slice(payload);
    p
}

/// UDP payload helper for tests: header + data, checksum left zero (allowed in IPv4).
pub fn build_udp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut l4 = Vec::with_capacity(8 + data.len());
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    l4.extend_from_slice(data);
    build_ipv4(src, dst, PROTO_UDP, &l4)
}

/// TCP segment helper for tests: 20-byte header with the given flags.
pub fn build_tcp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, flags: u8) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&sport.to_be_bytes());
    l4[2..4].copy_from_slice(&dport.to_be_bytes());
    l4[12] = 0x50;
    l4[13] = flags;
    build_ipv4(src, dst, PROTO_TCP, &l4)
}

/// ICMP echo helper for tests.
pub fn build_icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, reply: bool, id: u16) -> Vec<u8> {
    let mut l4 = vec![0u8; 8];
    l4[0] = if reply { 0 } else { 8 };
    l4[4..6].copy_from_slice(&id.to_be_bytes());
    build_ipv4(src, dst, PROTO_ICMP, &l4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_udp_and_tcp() {
        let a = Ipv4Addr::new(10, 1, 0, 1);
        let b = Ipv4Addr::new(10, 1, 0, 2);
        let udp = build_udp(a, 5000, b, 53, b"hi");
        let f = parse_flow(&udp).unwrap();
        assert_eq!(
            (f.src, f.dst, f.proto, f.sport, f.dport),
            (a, b, PROTO_UDP, 5000, 53)
        );
        assert_eq!(ipv4_dst(&udp), Some(b));
        let tcp = build_tcp(a, 40000, b, 22, TCP_SYN);
        let f = parse_flow(&tcp).unwrap();
        assert_eq!(f.dport, 22);
        assert_eq!(f.tcp_flags, TCP_SYN);
        assert!(parse_flow(&[0x60, 0, 0, 0]).is_none());
    }
}
