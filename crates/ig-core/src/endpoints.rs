//! Local endpoint candidates: every usable IPv4 address on this host paired
//! with the engine's UDP port. Shared with peers through the lighthouse so two
//! machines on the same LAN talk directly without touching the internet.

use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub fn local_candidates(port: u16, exclude: &[Ipv4Net]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return out;
    };
    for iface in ifaces {
        let IpAddr::V4(ip) = iface.ip() else { continue };
        if !usable(ip) {
            continue;
        }
        if exclude.iter().any(|n| n.contains(&ip)) {
            continue;
        }
        let sa = SocketAddr::new(IpAddr::V4(ip), port);
        if !out.contains(&sa) {
            out.push(sa);
        }
    }
    out.truncate(8);
    out
}

fn usable(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast())
}
