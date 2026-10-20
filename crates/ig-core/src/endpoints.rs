//! Local endpoint candidates: every usable address on this host paired with the
//! engine's UDP port. Shared with peers through the lighthouse so two machines
//! on the same LAN talk directly without touching the internet.

use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn local_candidates(
    port: u16,
    exclude4: &[Ipv4Net],
    exclude6: &[Ipv6Net],
    want_v6: bool,
) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return out;
    };
    for iface in ifaces {
        let ip = iface.ip();
        let ok = match ip {
            IpAddr::V4(v4) => usable_v4(v4) && !exclude4.iter().any(|n| n.contains(&v4)),
            IpAddr::V6(v6) => want_v6 && usable_v6(v6) && !exclude6.iter().any(|n| n.contains(&v6)),
        };
        if !ok {
            continue;
        }
        let sa = SocketAddr::new(ip, port);
        if !out.contains(&sa) {
            out.push(sa);
        }
    }
    // IPv4 first: more NATs, but also more likely to be reachable from anywhere.
    out.sort_by_key(|a| a.is_ipv6());
    out.truncate(10);
    out
}

/// IPv4 prefixes of the LANs this host is attached to, excluding overlay
/// prefixes. Used by the lighthouse to pick gateways for registered devices.
pub fn local_subnets(exclude4: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let mut out: Vec<Ipv4Net> = Vec::new();
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return out;
    };
    for iface in ifaces {
        let if_addrs::IfAddr::V4(v4) = iface.addr else {
            continue;
        };
        if !usable_v4(v4.ip) || exclude4.iter().any(|n| n.contains(&v4.ip)) {
            continue;
        }
        let Ok(net) = Ipv4Net::with_netmask(v4.ip, v4.netmask) else {
            continue;
        };
        let net = net.trunc();
        if net.prefix_len() == 32 || out.contains(&net) {
            continue;
        }
        out.push(net);
    }
    out.truncate(16);
    out
}

/// IPv6 prefixes of the LANs this host is attached to (global and ULA), excluding
/// overlay prefixes.
pub fn local_subnets6(exclude6: &[Ipv6Net]) -> Vec<Ipv6Net> {
    let mut out: Vec<Ipv6Net> = Vec::new();
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return out;
    };
    for iface in ifaces {
        let if_addrs::IfAddr::V6(v6) = iface.addr else {
            continue;
        };
        if !usable_v6(v6.ip) || exclude6.iter().any(|n| n.contains(&v6.ip)) {
            continue;
        }
        let Ok(net) = Ipv6Net::with_netmask(v6.ip, v6.netmask) else {
            continue;
        };
        let net = net.trunc();
        if net.prefix_len() == 128 || out.contains(&net) {
            continue;
        }
        out.push(net);
    }
    out.truncate(16);
    out
}

fn usable_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast())
}

fn usable_v6(ip: Ipv6Addr) -> bool {
    let seg0 = ip.segments()[0];
    let link_local = (seg0 & 0xffc0) == 0xfe80;
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || link_local
        || ip.to_ipv4_mapped().is_some())
}
