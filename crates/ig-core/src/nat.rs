//! Stateless address translation for gateway devices, IPv4 and IPv6.
//!
//! A gateway maps one overlay address to one physical address. Inbound packets
//! for the device get their destination rewritten before they enter the kernel;
//! replies get their source rewritten before they enter the tunnel. The kernel
//! does the many-to-one source NAT onto the LAN (see `ig_node::gateway_os`), so
//! this module only fixes checksums: the IPv4 header checksum, and the TCP, UDP
//! and ICMPv6 checksums, which all cover the addresses.

use crate::packet::{self, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use std::net::IpAddr;

/// RFC 1624 incremental update: replace the 16-bit words of `old` by `new`.
fn update_csum(csum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = (!csum) as u32;
    for i in (0..old.len()).step_by(2) {
        sum += (!u16::from_be_bytes([old[i], old[i + 1]])) as u32;
        sum += u16::from_be_bytes([new[i], new[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Clone, Copy)]
enum Field {
    Src,
    Dst,
}

fn rewrite(pkt: &mut [u8], field: Field, new: IpAddr) -> bool {
    let Some(flow) = packet::parse_flow(pkt) else {
        return false;
    };
    let (offset, len, new_bytes): (usize, usize, Vec<u8>) = match (new, flow.src.is_ipv4()) {
        (IpAddr::V4(a), true) => (
            match field {
                Field::Src => 12,
                Field::Dst => 16,
            },
            4,
            a.octets().to_vec(),
        ),
        (IpAddr::V6(a), false) => (
            match field {
                Field::Src => 8,
                Field::Dst => 24,
            },
            16,
            a.octets().to_vec(),
        ),
        _ => return false, // family mismatch
    };
    let old: Vec<u8> = pkt[offset..offset + len].to_vec();
    if old == new_bytes {
        return true;
    }
    pkt[offset..offset + len].copy_from_slice(&new_bytes);
    if len == 4 {
        let ip_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
        let c = update_csum(ip_csum, &old, &new_bytes);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
    }
    // Non-first fragments carry no transport header.
    let fragment =
        flow.sport == 0 && flow.dport == 0 && matches!(flow.proto, PROTO_TCP | PROTO_UDP);
    if fragment {
        return true;
    }
    let l4 = flow.l4_offset;
    let csum_at = match flow.proto {
        PROTO_TCP if pkt.len() >= l4 + 18 => Some(l4 + 16),
        PROTO_UDP if pkt.len() >= l4 + 8 => Some(l4 + 6),
        PROTO_ICMPV6 if pkt.len() >= l4 + 4 => Some(l4 + 2),
        _ => None,
    };
    if let Some(at) = csum_at {
        let cur = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
        // A zero IPv4 UDP checksum means "none"; leave it.
        if !(flow.proto == PROTO_UDP && cur == 0 && len == 4) {
            let mut c = update_csum(cur, &old, &new_bytes);
            if flow.proto == PROTO_UDP && c == 0 {
                c = 0xffff;
            }
            pkt[at..at + 2].copy_from_slice(&c.to_be_bytes());
        }
    }
    true
}

/// Rewrite the destination address in place. Returns false if the packet's
/// family does not match `new`.
pub fn rewrite_dst(pkt: &mut [u8], new: IpAddr) -> bool {
    rewrite(pkt, Field::Dst, new)
}

/// Rewrite the source address in place. Returns false if the packet's family
/// does not match `new`.
pub fn rewrite_src(pkt: &mut [u8], new: IpAddr) -> bool {
    rewrite(pkt, Field::Src, new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_icmp_echo, build_tcp, build_udp, l4_checksum, TCP_SYN};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip_header_ok(pkt: &[u8]) -> bool {
        let mut sum = 0u32;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xffff
    }

    fn l4_ok(pkt: &[u8]) -> bool {
        let f = packet::parse_flow(pkt).unwrap();
        let mut l4 = pkt[f.l4_offset..].to_vec();
        let at = match f.proto {
            PROTO_TCP => 16,
            PROTO_UDP => 6,
            PROTO_ICMPV6 => 2,
            _ => return true,
        };
        let stored = u16::from_be_bytes([l4[at], l4[at + 1]]);
        l4[at] = 0;
        l4[at + 1] = 0;
        l4_checksum(f.src, f.dst, f.proto, &l4) == stored
    }

    #[test]
    fn ipv4_rewrites_keep_checksums_valid() {
        let a: IpAddr = "10.90.0.7".parse().unwrap();
        let dev: IpAddr = "10.90.0.50".parse().unwrap();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mut udp = build_udp(a, 5000, dev, 53, b"hello device");
        assert!(l4_ok(&udp));
        assert!(rewrite_dst(&mut udp, target));
        assert_eq!(&udp[16..20], &[192, 168, 1, 50]);
        assert!(ip_header_ok(&udp) && l4_ok(&udp));
        let mut reply = build_tcp(target, 80, a, 5000, TCP_SYN | 0x10);
        assert!(rewrite_src(&mut reply, dev));
        assert_eq!(&reply[12..16], &[10, 90, 0, 50]);
        assert!(ip_header_ok(&reply) && l4_ok(&reply));
        // Family mismatch is refused.
        assert!(!rewrite_dst(&mut udp, "fd00::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_rewrites_keep_transport_checksums_valid() {
        let a: IpAddr = "fd42::7".parse().unwrap();
        let dev: IpAddr = "fd42::50".parse().unwrap();
        let target: IpAddr = IpAddr::V6("fd70::50".parse::<Ipv6Addr>().unwrap());
        let mut udp = build_udp(a, 5000, dev, 9100, b"print");
        assert!(rewrite_dst(&mut udp, target));
        assert_eq!(packet::dst(&udp), Some(target));
        assert!(l4_ok(&udp));
        let mut tcp = build_tcp(target, 9100, a, 5000, TCP_SYN | 0x10);
        assert!(rewrite_src(&mut tcp, dev));
        assert_eq!(packet::src(&tcp), Some(dev));
        assert!(l4_ok(&tcp));
        // ICMPv6 echo: its checksum covers the addresses too.
        let mut echo = build_icmp_echo(a, dev, false, 3);
        assert!(l4_ok(&echo));
        assert!(rewrite_dst(&mut echo, target));
        assert!(l4_ok(&echo));
    }
}
