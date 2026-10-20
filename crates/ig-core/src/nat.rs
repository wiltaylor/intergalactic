//! Stateless IPv4 address translation for gateway devices.
//!
//! A gateway maps one overlay address to one physical address. Inbound packets
//! for the device get their destination rewritten before they enter the kernel;
//! replies get their source rewritten before they enter the tunnel. The kernel
//! does the many-to-one source NAT onto the LAN (see `ig_node::gateway_os`), so
//! this module only needs to fix the IPv4 header checksum and the TCP/UDP
//! checksums, which both cover the addresses.

use crate::packet::{PROTO_TCP, PROTO_UDP};
use std::net::Ipv4Addr;

/// RFC 1624 incremental checksum update: replace 32-bit `old` by `new`.
fn update_csum(csum: u16, old: [u8; 4], new: [u8; 4]) -> u16 {
    let mut sum = (!csum) as u32;
    for i in (0..4).step_by(2) {
        sum += (!u16::from_be_bytes([old[i], old[i + 1]])) as u32;
        sum += u16::from_be_bytes([new[i], new[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn rewrite(pkt: &mut [u8], offset: usize, new: Ipv4Addr) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return false;
    }
    let old: [u8; 4] = pkt[offset..offset + 4].try_into().unwrap();
    let new_b = new.octets();
    if old == new_b {
        return true;
    }
    pkt[offset..offset + 4].copy_from_slice(&new_b);
    let ip_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
    let c = update_csum(ip_csum, old, new_b);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());

    let frag_offset = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
    if frag_offset != 0 {
        return true; // no transport header in later fragments
    }
    let proto = pkt[9];
    let csum_at = match proto {
        PROTO_TCP if pkt.len() >= ihl + 18 => Some(ihl + 16),
        PROTO_UDP if pkt.len() >= ihl + 8 => Some(ihl + 6),
        _ => None,
    };
    if let Some(at) = csum_at {
        let cur = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
        // A zero UDP checksum means "none"; leave it.
        if !(proto == PROTO_UDP && cur == 0) {
            let mut c = update_csum(cur, old, new_b);
            if proto == PROTO_UDP && c == 0 {
                c = 0xffff;
            }
            pkt[at..at + 2].copy_from_slice(&c.to_be_bytes());
        }
    }
    true
}

/// Rewrite the destination address in place. Returns false for non-IPv4 input.
pub fn rewrite_dst(pkt: &mut [u8], new: Ipv4Addr) -> bool {
    rewrite(pkt, 16, new)
}

/// Rewrite the source address in place. Returns false for non-IPv4 input.
pub fn rewrite_src(pkt: &mut [u8], new: Ipv4Addr) -> bool {
    rewrite(pkt, 12, new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_tcp, build_udp, l4_checksum, TCP_SYN};
    use std::net::IpAddr;

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
        let src: Ipv4Addr = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst: Ipv4Addr = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let proto = pkt[9];
        let mut l4 = pkt[20..].to_vec();
        let at = if proto == PROTO_TCP { 16 } else { 6 };
        let stored = u16::from_be_bytes([l4[at], l4[at + 1]]);
        l4[at] = 0;
        l4[at + 1] = 0;
        l4_checksum(IpAddr::V4(src), IpAddr::V4(dst), proto, &l4) == stored
    }

    #[test]
    fn rewrites_keep_checksums_valid() {
        let a: IpAddr = "10.90.0.7".parse().unwrap();
        let dev: IpAddr = "10.90.0.50".parse().unwrap();
        let target = Ipv4Addr::new(192, 168, 1, 50);
        let mut udp = build_udp(a, 5000, dev, 53, b"hello device");
        assert!(l4_ok(&udp));
        assert!(rewrite_dst(&mut udp, target));
        assert_eq!(&udp[16..20], &target.octets());
        assert!(ip_header_ok(&udp) && l4_ok(&udp));
        // Reply direction: source rewritten back to the overlay address.
        let mut reply = build_tcp(IpAddr::V4(target), 80, a, 5000, TCP_SYN | 0x10);
        assert!(rewrite_src(&mut reply, Ipv4Addr::new(10, 90, 0, 50)));
        assert_eq!(&reply[12..16], &[10, 90, 0, 50]);
        assert!(ip_header_ok(&reply) && l4_ok(&reply));
        // IPv6 is refused.
        let mut v6 = build_udp(
            "fd00::1".parse().unwrap(),
            1,
            "fd00::2".parse().unwrap(),
            2,
            b"x",
        );
        assert!(!rewrite_dst(&mut v6, target));
    }
}
