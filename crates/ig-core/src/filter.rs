//! Stateful inbound filter that enforces a network [`Policy`] per peer.
//!
//! Rules describe which *new inbound flows* a member accepts. Flows the member
//! opened itself are tracked when packets go out, so replies always get in.
//! Flows admitted by a rule are tracked too, so the rest of the conversation
//! passes without re-matching. Anything else is dropped before it reaches the OS.

use crate::packet::{self, Flow, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_SYN};
use ig_proto::{Policy, Proto};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const TCP_IDLE: Duration = Duration::from_secs(3600);
const UDP_IDLE: Duration = Duration::from_secs(120);
const ICMP_IDLE: Duration = Duration::from_secs(30);
const SWEEP_AT: usize = 4096;

/// Key from *our* point of view: (proto, our ip, our port, peer ip, peer port).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Key {
    proto: u8,
    local: IpAddr,
    lport: u16,
    remote: IpAddr,
    rport: u16,
}

#[derive(Default)]
pub struct PeerFilter {
    flows: HashMap<Key, Instant>,
}

impl PeerFilter {
    pub fn new() -> Self {
        Self::default()
    }

    fn idle_for(proto: u8) -> Duration {
        match proto {
            PROTO_TCP => TCP_IDLE,
            PROTO_UDP => UDP_IDLE,
            _ => ICMP_IDLE,
        }
    }

    fn key_outbound(f: &Flow) -> Key {
        // For ICMP echo, "ports" are (id, type); normalise type to the request so
        // the reply (type 0) matches the request (type 8).
        let (lport, rport) = match f.proto {
            PROTO_ICMP | PROTO_ICMPV6 => (f.sport, 8),
            _ => (f.sport, f.dport),
        };
        Key {
            proto: f.proto,
            local: f.src,
            lport,
            remote: f.dst,
            rport,
        }
    }

    fn key_inbound(f: &Flow) -> Key {
        let (lport, rport) = match f.proto {
            PROTO_ICMP | PROTO_ICMPV6 => (f.sport, 8),
            _ => (f.dport, f.sport),
        };
        Key {
            proto: f.proto,
            local: f.dst,
            lport,
            remote: f.src,
            rport,
        }
    }

    fn touch(&mut self, key: Key, now: Instant) {
        if self.flows.len() >= SWEEP_AT {
            self.flows
                .retain(|k, t| now.duration_since(*t) < Self::idle_for(k.proto));
        }
        self.flows.insert(key, now);
    }

    /// Record a packet we are sending to the peer.
    pub fn note_outbound(&mut self, pkt: &[u8]) {
        if let Some(f) = packet::parse_flow(pkt) {
            self.touch(Self::key_outbound(&f), Instant::now());
        }
    }

    /// Decide whether a decrypted packet from the peer may be delivered.
    pub fn allow_inbound(&mut self, policy: &Policy, pkt: &[u8]) -> bool {
        if policy.is_allow_all() {
            return true;
        }
        let Some(f) = packet::parse_flow(pkt) else {
            return false;
        };
        let now = Instant::now();
        let key = Self::key_inbound(&f);
        if let Some(t) = self.flows.get(&key) {
            if now.duration_since(*t) < Self::idle_for(f.proto) {
                self.flows.insert(key, now);
                return true;
            }
            self.flows.remove(&key);
        }
        let allowed = match f.proto {
            PROTO_TCP => {
                // Only a bare SYN may open a flow. Anything else without state is
                // a stray segment; the kernel would answer with RST and leak that
                // the port exists, so drop it here instead.
                let is_syn = f.tcp_flags & TCP_SYN != 0 && f.tcp_flags & TCP_ACK == 0;
                is_syn && rule_allows(policy, Proto::Tcp, f.dport)
            }
            PROTO_UDP => rule_allows(policy, Proto::Udp, f.dport),
            PROTO_ICMP => match f.dport as u8 {
                // Echo request: needs an explicit icmp rule.
                8 => rule_allows(policy, Proto::Icmp, 0),
                // Echo reply without a matching request was handled above; drop.
                0 => false,
                // Destination unreachable, time exceeded, parameter problem:
                // harmless diagnostics about traffic we sent.
                3 | 11 | 12 => true,
                _ => false,
            },
            PROTO_ICMPV6 => match f.dport as u8 {
                128 => rule_allows(policy, Proto::Icmp, 0),
                129 => false,
                // Destination unreachable, packet too big, time exceeded, parameter problem.
                1..=4 => true,
                _ => false,
            },
            _ => false,
        };
        if allowed {
            self.touch(key, now);
        }
        allowed
    }
}

fn rule_allows(policy: &Policy, proto: Proto, port: u16) -> bool {
    policy
        .rules
        .iter()
        .any(|r| r.proto == proto && (proto == Proto::Icmp || r.matches_port(port)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_icmp_echo, build_tcp, build_udp};
    use ig_proto::Rule;

    fn me() -> IpAddr {
        "10.9.0.1".parse().unwrap()
    }
    fn peer() -> IpAddr {
        "10.9.0.2".parse().unwrap()
    }

    fn policy(rules: &[&str]) -> Policy {
        Policy {
            rules: rules.iter().map(|r| r.parse::<Rule>().unwrap()).collect(),
        }
    }

    #[test]
    fn allow_all_passes_everything() {
        let mut f = PeerFilter::new();
        assert!(f.allow_inbound(
            &Policy::allow_all(),
            &build_tcp(peer(), 1, me(), 2, TCP_ACK)
        ));
    }

    #[test]
    fn tcp_rules_gate_new_connections_only() {
        let p = policy(&["tcp:22"]);
        let mut f = PeerFilter::new();
        // New SSH connection: allowed and tracked.
        assert!(f.allow_inbound(&p, &build_tcp(peer(), 40000, me(), 22, TCP_SYN)));
        assert!(f.allow_inbound(&p, &build_tcp(peer(), 40000, me(), 22, TCP_ACK)));
        // New connection to another port: dropped.
        assert!(!f.allow_inbound(&p, &build_tcp(peer(), 40001, me(), 80, TCP_SYN)));
        // Stray ACK to unknown flow: dropped.
        assert!(!f.allow_inbound(&p, &build_tcp(peer(), 40002, me(), 80, TCP_ACK)));
    }

    #[test]
    fn replies_to_our_own_connections_pass() {
        let p = policy(&["icmp"]);
        let mut f = PeerFilter::new();
        // We connect out to the peer's web server; its SYN-ACK must get in.
        f.note_outbound(&build_tcp(me(), 50000, peer(), 443, TCP_SYN));
        assert!(f.allow_inbound(&p, &build_tcp(peer(), 443, me(), 50000, TCP_SYN | TCP_ACK)));
        // DNS query out, answer in.
        f.note_outbound(&build_udp(me(), 5353, peer(), 53, b"q"));
        assert!(f.allow_inbound(&p, &build_udp(peer(), 53, me(), 5353, b"a")));
        // Unsolicited UDP: dropped.
        assert!(!f.allow_inbound(&p, &build_udp(peer(), 53, me(), 5354, b"a")));
    }

    #[test]
    fn ipv6_flows_are_tracked_too() {
        let p = policy(&["tcp:22"]);
        let me6: IpAddr = "fd00::1".parse().unwrap();
        let peer6: IpAddr = "fd00::2".parse().unwrap();
        let mut f = PeerFilter::new();
        assert!(f.allow_inbound(&p, &build_tcp(peer6, 4000, me6, 22, TCP_SYN)));
        assert!(!f.allow_inbound(&p, &build_tcp(peer6, 4001, me6, 80, TCP_SYN)));
        // ICMPv6 echo needs a rule; packet-too-big is always fine.
        assert!(!f.allow_inbound(&p, &build_icmp_echo(peer6, me6, false, 1)));
        f.note_outbound(&build_icmp_echo(me6, peer6, false, 5));
        assert!(f.allow_inbound(&p, &build_icmp_echo(peer6, me6, true, 5)));
    }

    #[test]
    fn icmp_echo_handling() {
        let no_icmp = policy(&["tcp:22"]);
        let with_icmp = policy(&["icmp"]);
        let mut f = PeerFilter::new();
        assert!(!f.allow_inbound(&no_icmp, &build_icmp_echo(peer(), me(), false, 7)));
        assert!(f.allow_inbound(&with_icmp, &build_icmp_echo(peer(), me(), false, 7)));
        // Our ping out, reply in, even without an icmp rule.
        f.note_outbound(&build_icmp_echo(me(), peer(), false, 99));
        assert!(f.allow_inbound(&no_icmp, &build_icmp_echo(peer(), me(), true, 99)));
        assert!(!f.allow_inbound(&no_icmp, &build_icmp_echo(peer(), me(), true, 100)));
    }
}
