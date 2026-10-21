//! In-engine DNS responder for peer names.
//!
//! Each network reserves its first host address (`10.90.0.1`, `fd..::1`) as a
//! name server. The OS is told to send queries for `<network>.<domain>` there.
//! Packets to that address never leave the machine: the engine answers them
//! straight back into the TUN. This works the same on Linux, Windows and
//! Android and needs no listening socket.
//!
//! Names: `<label>.<network>.<domain>` and the shortcut `<label>.<domain>`
//! (first network that has the label wins). A, AAAA and PTR are supported.
//!
//! Platforms whose resolver cannot do split DNS (Android) send *every* query
//! to the responder. For names outside the overlay zones the engine then acts
//! as a plain forwarder: [`Forwarder`] relays the raw query over a UDP socket
//! that the [`SocketProtector`] keeps out of the tunnel, and the upstream
//! answer is written back into the TUN as if the responder had produced it.
//! With no upstreams configured (desktop nodes) such names get NXDOMAIN, as
//! before; the OS resolver only sends overlay names there anyway.

use crate::engine::SocketProtector;
use crate::packet::{self, PROTO_UDP};
use ipnet::IpNet;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

pub const DNS_PORT: u16 = 53;
const TTL: u32 = 60;
/// How long to wait for one upstream before trying the next.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// Queries in flight towards upstreams at once; more are dropped.
pub const MAX_IN_FLIGHT: usize = 64;
/// Largest UDP DNS answer we accept from an upstream.
const MAX_ANSWER: usize = 4096;

#[derive(Default, Clone, Debug)]
pub struct DnsTable {
    /// lowercase fqdn (no trailing dot) -> addresses
    names: HashMap<String, Vec<IpAddr>>,
    reverse: HashMap<IpAddr, String>,
    /// Suffixes we are authoritative for (lowercase, no trailing dot).
    zones: Vec<String>,
    /// Overlay ranges; reverse lookups inside them are ours.
    ranges: Vec<IpNet>,
}

impl DnsTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_zone(&mut self, zone: &str) {
        let z = zone.trim_matches('.').to_ascii_lowercase();
        if !z.is_empty() && !self.zones.contains(&z) {
            self.zones.push(z);
        }
    }

    /// Register an overlay range, so PTR queries inside it are answered
    /// locally instead of being forwarded.
    pub fn add_range(&mut self, range: IpNet) {
        if !self.ranges.contains(&range) {
            self.ranges.push(range);
        }
    }

    /// Register `label.network.domain`, and `label.domain` if not already taken.
    pub fn add(&mut self, label: &str, network: &str, domain: &str, addrs: &[IpAddr]) {
        let domain = domain.trim_matches('.').to_ascii_lowercase();
        let fqdn = format!("{}.{}.{}", label, network, domain).to_ascii_lowercase();
        let short = format!("{}.{}", label, domain).to_ascii_lowercase();
        self.names.insert(fqdn.clone(), addrs.to_vec());
        self.names.entry(short).or_insert_with(|| addrs.to_vec());
        for a in addrs {
            self.reverse.entry(*a).or_insert_with(|| fqdn.clone());
        }
    }

    pub fn lookup(&self, name: &str) -> Option<&Vec<IpAddr>> {
        self.names
            .get(&name.trim_end_matches('.').to_ascii_lowercase())
    }

    /// Is this a name the responder must answer itself? True for names under
    /// an overlay zone and for reverse names of overlay addresses (known
    /// peers and anything inside a registered range). Everything else may be
    /// forwarded.
    pub fn is_ours(&self, name: &str) -> bool {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        if self
            .zones
            .iter()
            .any(|z| n == *z || n.ends_with(&format!(".{z}")))
        {
            return true;
        }
        match ptr_to_ip(&n) {
            Some(ip) => {
                self.reverse.contains_key(&ip) || self.ranges.iter().any(|r| r.contains(&ip))
            }
            None => n.ends_with(".in-addr.arpa") || n.ends_with(".ip6.arpa"),
        }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

const QTYPE_A: u16 = 1;
const QTYPE_PTR: u16 = 12;
const QTYPE_AAAA: u16 = 28;
const QTYPE_ANY: u16 = 255;

const RCODE_OK: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;

/// Parse a DNS query message and build the response message.
pub fn respond(table: &DnsTable, msg: &[u8]) -> Option<Vec<u8>> {
    if msg.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 != 0 {
        return None; // a response, not a query
    }
    let opcode = ((flags >> 11) & 0xf) as u8;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let (qname, qend) = read_name(msg, 12)?;
    if msg.len() < qend + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[qend], msg[qend + 1]]);
    let qclass = u16::from_be_bytes([msg[qend + 2], msg[qend + 3]]);
    let question = &msg[12..qend + 4];

    let mut answers: Vec<Vec<u8>> = Vec::new();
    let rcode = if opcode != 0 || qdcount != 1 {
        RCODE_NOTIMP
    } else if qclass != 1 && qclass != 255 {
        RCODE_NXDOMAIN
    } else if qtype == QTYPE_PTR {
        match ptr_to_ip(&qname).and_then(|ip| table.reverse.get(&ip)) {
            Some(name) => {
                answers.push(rr(QTYPE_PTR, &encode_name(name)));
                RCODE_OK
            }
            None => RCODE_NXDOMAIN,
        }
    } else {
        match table.lookup(&qname) {
            Some(addrs) => {
                for a in addrs {
                    match (a, qtype) {
                        (IpAddr::V4(v4), QTYPE_A | QTYPE_ANY) => {
                            answers.push(rr(QTYPE_A, &v4.octets()))
                        }
                        (IpAddr::V6(v6), QTYPE_AAAA | QTYPE_ANY) => {
                            answers.push(rr(QTYPE_AAAA, &v6.octets()))
                        }
                        _ => {}
                    }
                }
                // Name exists but no record of this type: NOERROR with empty answer.
                RCODE_OK
            }
            None => RCODE_NXDOMAIN,
        }
    };

    let mut out =
        Vec::with_capacity(12 + question.len() + answers.iter().map(|a| a.len()).sum::<usize>());
    out.extend_from_slice(&msg[0..2]); // id
    let rd = flags & 0x0100;
    // QR=1, AA=1, RD copied, RA=1
    let rflags: u16 = 0x8000 | 0x0400 | rd | 0x0080 | rcode as u16;
    out.extend_from_slice(&rflags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(question);
    for a in answers {
        out.extend_from_slice(&a);
    }
    Some(out)
}

/// Name asked for by a query message, if it parses as one.
fn question_name(msg: &[u8]) -> Option<String> {
    if msg.len() < 12 || u16::from_be_bytes([msg[2], msg[3]]) & 0x8000 != 0 {
        return None;
    }
    read_name(msg, 12).map(|(n, _)| n)
}

/// A query that must go to an upstream resolver. `reply_packet` turns the
/// upstream's answer into the TUN packet the client expects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardRequest {
    /// Raw DNS message as the client sent it.
    pub query: Vec<u8>,
    /// Our responder address the client sent the query to.
    pub server: IpAddr,
    pub client: IpAddr,
    pub client_port: u16,
}

impl ForwardRequest {
    /// Wrap an upstream answer in IP/UDP, from the responder back to the client.
    pub fn reply_packet(&self, answer: &[u8]) -> Vec<u8> {
        packet::build_udp(self.server, DNS_PORT, self.client, self.client_port, answer)
    }
}

/// What to do with a packet addressed to a responder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsAction {
    /// Write this packet back into the TUN.
    Reply(Vec<u8>),
    /// Ask an upstream and write its answer back with [`ForwardRequest::reply_packet`].
    Forward(ForwardRequest),
    /// Not a DNS query we can act on.
    Ignore,
}

/// Decide how a packet to the responder address is answered.
///
/// Overlay names (and unknown names under an overlay zone) are always
/// answered locally. Other names are forwarded when `can_forward` is set and
/// get a local negative answer otherwise.
pub fn handle_packet(table: &DnsTable, query_pkt: &[u8], can_forward: bool) -> DnsAction {
    let Some(flow) = packet::parse_flow(query_pkt) else {
        return DnsAction::Ignore;
    };
    if flow.proto != PROTO_UDP || flow.dport != DNS_PORT {
        return DnsAction::Ignore;
    }
    let l4 = &query_pkt[flow.l4_offset..];
    if l4.len() < 8 {
        return DnsAction::Ignore;
    }
    let udp_len = u16::from_be_bytes([l4[4], l4[5]]) as usize;
    let Some(payload) = l4.get(8..udp_len.min(l4.len())) else {
        return DnsAction::Ignore;
    };
    if can_forward {
        if let Some(name) = question_name(payload) {
            if !table.is_ours(&name) {
                return DnsAction::Forward(ForwardRequest {
                    query: payload.to_vec(),
                    server: flow.dst,
                    client: flow.src,
                    client_port: flow.sport,
                });
            }
        }
    }
    match respond(table, payload) {
        Some(answer) => DnsAction::Reply(packet::build_udp(
            flow.dst, DNS_PORT, flow.src, flow.sport, &answer,
        )),
        None => DnsAction::Ignore,
    }
}

/// Build the IP/UDP reply packet for a query packet that arrived from the TUN,
/// answering from the table only.
pub fn reply_packet(table: &DnsTable, query_pkt: &[u8]) -> Option<Vec<u8>> {
    match handle_packet(table, query_pkt, false) {
        DnsAction::Reply(p) => Some(p),
        _ => None,
    }
}

/// Relays queries for non-overlay names to upstream resolvers.
///
/// Each query gets its own short-lived UDP socket, protected through the
/// engine's [`SocketProtector`] so Android routes it over the underlying
/// network and not back into the VPN. Upstreams are tried in order; one that
/// does not answer within [`UPSTREAM_TIMEOUT`] is skipped for that query.
pub struct Forwarder {
    upstreams: RwLock<Vec<SocketAddr>>,
    in_flight: Arc<tokio::sync::Semaphore>,
    protector: Arc<dyn SocketProtector>,
    timeout: Duration,
}

impl Forwarder {
    pub fn new(upstreams: Vec<SocketAddr>, protector: Arc<dyn SocketProtector>) -> Self {
        Self {
            upstreams: RwLock::new(upstreams),
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)),
            protector,
            timeout: UPSTREAM_TIMEOUT,
        }
    }

    /// Override the per-upstream timeout (tests).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn set_upstreams(&self, upstreams: Vec<SocketAddr>) {
        tracing::info!(?upstreams, "upstream dns servers");
        *self.upstreams.write() = upstreams;
    }

    pub fn upstreams(&self) -> Vec<SocketAddr> {
        self.upstreams.read().clone()
    }

    pub fn has_upstreams(&self) -> bool {
        !self.upstreams.read().is_empty()
    }

    /// Resolve `req` in the background and hand the finished TUN packet to
    /// `deliver`. Drops the query when too many are in flight, when no
    /// upstream answers, or when called outside a tokio runtime.
    pub fn forward(&self, req: ForwardRequest, deliver: impl FnOnce(Vec<u8>) + Send + 'static) {
        let Ok(permit) = self.in_flight.clone().try_acquire_owned() else {
            tracing::debug!("dns forward queue full; dropping query");
            return;
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            tracing::debug!("dns forward outside a runtime; dropping query");
            return;
        };
        let upstreams = self.upstreams();
        let protector = self.protector.clone();
        let timeout = self.timeout;
        rt.spawn(async move {
            let _permit = permit;
            if let Some(answer) = resolve(&upstreams, &req.query, &*protector, timeout).await {
                deliver(req.reply_packet(&answer));
            }
        });
    }
}

/// Send `query` to each upstream in turn until one answers with a matching
/// response.
pub async fn resolve(
    upstreams: &[SocketAddr],
    query: &[u8],
    protector: &dyn SocketProtector,
    timeout: Duration,
) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    for up in upstreams {
        let bind: SocketAddr = if up.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let sock = match UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(upstream = %up, error = %e, "dns forward bind failed");
                continue;
            }
        };
        protector.protect(raw_socket(&sock));
        if let Err(e) = sock.send_to(query, up).await {
            tracing::debug!(upstream = %up, error = %e, "dns forward send failed");
            continue;
        }
        let mut buf = vec![0u8; MAX_ANSWER];
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    let is_response = n >= 12 && buf[2] & 0x80 != 0;
                    if from == *up && is_response && buf[..2] == query[..2] {
                        return Some(buf[..n].to_vec());
                    }
                    // Stray or spoofed datagram: keep waiting for the real answer.
                }
                Ok(Err(e)) => {
                    tracing::debug!(upstream = %up, error = %e, "dns forward recv failed");
                    break;
                }
                Err(_) => {
                    tracing::debug!(upstream = %up, "dns upstream timed out");
                    break;
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn raw_socket(s: &UdpSocket) -> i64 {
    use std::os::fd::AsRawFd;
    s.as_raw_fd() as i64
}

#[cfg(windows)]
fn raw_socket(s: &UdpSocket) -> i64 {
    use std::os::windows::io::AsRawSocket;
    s.as_raw_socket() as i64
}

fn rr(rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + rdata.len());
    v.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
    v.extend_from_slice(&rtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&TTL.to_be_bytes());
    v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    v.extend_from_slice(rdata);
    v
}

fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut hops = 0;
    let mut end = None;
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer (rare in questions, but legal).
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            pos = ptr;
            hops += 1;
            if hops > 8 {
                return None;
            }
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_string());
        pos += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        v.push(b.len().min(63) as u8);
        v.extend_from_slice(&b[..b.len().min(63)]);
    }
    v.push(0);
    v
}

fn ptr_to_ip(name: &str) -> Option<IpAddr> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = n.strip_suffix(".in-addr.arpa") {
        let mut parts: Vec<u8> = rest
            .split('.')
            .map(|p| p.parse::<u8>())
            .collect::<Result<_, _>>()
            .ok()?;
        if parts.len() != 4 {
            return None;
        }
        parts.reverse();
        return Some(IpAddr::V4(std::net::Ipv4Addr::new(
            parts[0], parts[1], parts[2], parts[3],
        )));
    }
    if let Some(rest) = n.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<u8> = rest
            .split('.')
            .map(|p| u8::from_str_radix(p, 16))
            .collect::<Result<_, _>>()
            .ok()?;
        if nibbles.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, pair) in nibbles
            .iter()
            .rev()
            .collect::<Vec<_>>()
            .chunks(2)
            .enumerate()
        {
            bytes[i] = (pair[0] << 4) | pair[1];
        }
        return Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&encode_name(name));
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    fn table() -> DnsTable {
        let mut t = DnsTable::new();
        t.add_zone("ig.internal");
        t.add(
            "laptop",
            "dev",
            "ig.internal",
            &["10.90.0.2".parse().unwrap(), "fd42::2".parse().unwrap()],
        );
        t.add(
            "laptop",
            "game",
            "ig.internal",
            &["10.91.0.2".parse().unwrap()],
        );
        t
    }

    #[test]
    fn answers_a_and_aaaa() {
        let t = table();
        let r = respond(&t, &query("laptop.dev.ig.internal", QTYPE_A)).unwrap();
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[3] & 0x0f, RCODE_OK);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "one A answer");
        assert_eq!(&r[r.len() - 4..], &[10, 90, 0, 2]);
        let r6 = respond(&t, &query("LAPTOP.dev.ig.internal.", QTYPE_AAAA)).unwrap();
        assert_eq!(u16::from_be_bytes([r6[6], r6[7]]), 1);
        assert_eq!(r6[r6.len() - 16..][..2], [0xfd, 0x42]);
        // Shortcut name: first registration wins.
        let s = respond(&t, &query("laptop.ig.internal", QTYPE_A)).unwrap();
        assert_eq!(&s[s.len() - 4..], &[10, 90, 0, 2]);
        let nx = respond(&t, &query("nope.dev.ig.internal", QTYPE_A)).unwrap();
        assert_eq!(nx[3] & 0x0f, RCODE_NXDOMAIN);
        assert!(t.is_ours("x.dev.ig.internal") && !t.is_ours("example.com"));
    }

    #[test]
    fn answers_ptr() {
        let t = table();
        let r = respond(&t, &query("2.0.90.10.in-addr.arpa", QTYPE_PTR)).unwrap();
        assert_eq!(r[3] & 0x0f, RCODE_OK);
        let (name, _) =
            read_name(&r, r.len() - encode_name("laptop.dev.ig.internal").len()).unwrap();
        assert_eq!(name, "laptop.dev.ig.internal");
        let v6 = "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.4.d.f.ip6.arpa";
        let r6 = respond(&t, &query(v6, QTYPE_PTR)).unwrap();
        assert_eq!(r6[3] & 0x0f, RCODE_OK);
    }

    #[test]
    fn reply_packet_swaps_addresses() {
        let t = table();
        let me: IpAddr = "10.90.0.5".parse().unwrap();
        let server: IpAddr = "10.90.0.1".parse().unwrap();
        let q = packet::build_udp(
            me,
            40000,
            server,
            53,
            &query("laptop.dev.ig.internal", QTYPE_A),
        );
        let reply = reply_packet(&t, &q).unwrap();
        let f = packet::parse_flow(&reply).unwrap();
        assert_eq!((f.src, f.dst, f.sport, f.dport), (server, me, 53, 40000));
        assert!(reply_packet(&t, &packet::build_udp(me, 1, server, 54, b"x")).is_none());
    }

    fn ranged_table() -> DnsTable {
        let mut t = table();
        t.add_range("10.90.0.0/24".parse().unwrap());
        t.add_range("fd42::/64".parse().unwrap());
        t
    }

    fn rcode_of(pkt: &[u8]) -> u8 {
        let f = packet::parse_flow(pkt).unwrap();
        pkt[f.l4_offset + 8 + 3] & 0x0f
    }

    #[test]
    fn forwarding_decision() {
        let t = ranged_table();
        let me: IpAddr = "10.90.0.5".parse().unwrap();
        let server: IpAddr = "10.90.0.1".parse().unwrap();
        let pkt =
            |name: &str, qtype: u16| packet::build_udp(me, 40000, server, 53, &query(name, qtype));

        // Overlay name: answered locally, forwarding or not.
        match handle_packet(&t, &pkt("laptop.dev.ig.internal", QTYPE_A), true) {
            DnsAction::Reply(r) => assert_eq!(rcode_of(&r), RCODE_OK),
            other => panic!("expected local answer, got {other:?}"),
        }
        // Unknown name under an overlay zone keeps the negative answer.
        match handle_packet(&t, &pkt("nope.dev.ig.internal", QTYPE_A), true) {
            DnsAction::Reply(r) => assert_eq!(rcode_of(&r), RCODE_NXDOMAIN),
            other => panic!("expected NXDOMAIN, got {other:?}"),
        }
        // Public name: forwarded when upstreams exist ...
        match handle_packet(&t, &pkt("example.com", QTYPE_A), true) {
            DnsAction::Forward(req) => {
                assert_eq!(req.query, query("example.com", QTYPE_A));
                assert_eq!(
                    (req.server, req.client, req.client_port),
                    (server, me, 40000)
                );
                let f = packet::parse_flow(&req.reply_packet(b"answer")).unwrap();
                assert_eq!((f.src, f.dst, f.sport, f.dport), (server, me, 53, 40000));
            }
            other => panic!("expected forward, got {other:?}"),
        }
        // ... and NXDOMAIN without (desktop behaviour).
        match handle_packet(&t, &pkt("example.com", QTYPE_A), false) {
            DnsAction::Reply(r) => assert_eq!(rcode_of(&r), RCODE_NXDOMAIN),
            other => panic!("expected NXDOMAIN, got {other:?}"),
        }
        // Reverse lookups: overlay range stays local, public address is forwarded.
        match handle_packet(&t, &pkt("77.0.90.10.in-addr.arpa", QTYPE_PTR), true) {
            DnsAction::Reply(r) => assert_eq!(rcode_of(&r), RCODE_NXDOMAIN),
            other => panic!("expected local PTR answer, got {other:?}"),
        }
        assert!(matches!(
            handle_packet(&t, &pkt("8.8.8.8.in-addr.arpa", QTYPE_PTR), true),
            DnsAction::Forward(_)
        ));
        // Not DNS at all.
        assert_eq!(
            handle_packet(&t, &packet::build_udp(me, 1, server, 54, b"x"), true),
            DnsAction::Ignore
        );
    }

    /// A fake upstream on loopback that answers every query with one A record.
    async fn fake_upstream(answer: [u8; 4]) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let q = &buf[..n];
                let (_, qend) = read_name(q, 12).unwrap();
                let mut r = q[..2].to_vec();
                r.extend_from_slice(&0x8180u16.to_be_bytes());
                r.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
                r.extend_from_slice(&q[12..qend + 4]);
                r.extend_from_slice(&rr(QTYPE_A, &answer));
                let _ = sock.send_to(&r, from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn forwards_to_upstream_and_skips_silent_ones() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let live = fake_upstream([93, 184, 216, 34]).await;
        let fwd = Forwarder::new(
            vec![silent_addr, live],
            Arc::new(crate::engine::NoProtector),
        )
        .with_timeout(Duration::from_millis(200));

        let me: IpAddr = "10.90.0.5".parse().unwrap();
        let server: IpAddr = "10.90.0.1".parse().unwrap();
        let t = ranged_table();
        let pkt = packet::build_udp(me, 40000, server, 53, &query("example.com", QTYPE_A));
        let DnsAction::Forward(req) = handle_packet(&t, &pkt, fwd.has_upstreams()) else {
            panic!("expected forward");
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        fwd.forward(req, move |reply| {
            let _ = tx.send(reply);
        });
        let reply = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("upstream answer in time")
            .unwrap();
        let f = packet::parse_flow(&reply).unwrap();
        assert_eq!((f.src, f.dst, f.sport, f.dport), (server, me, 53, 40000));
        assert_eq!(&reply[reply.len() - 4..], &[93, 184, 216, 34]);
        assert_eq!(
            &reply[f.l4_offset + 8..][..2],
            &[0x12, 0x34],
            "query id kept"
        );

        // Only silent upstreams: no answer, no panic.
        let dead = Forwarder::new(vec![silent_addr], Arc::new(crate::engine::NoProtector))
            .with_timeout(Duration::from_millis(100));
        let none = resolve(
            &dead.upstreams(),
            &query("example.com", QTYPE_A),
            &crate::engine::NoProtector,
            dead.timeout,
        )
        .await;
        assert!(none.is_none());
    }
}
