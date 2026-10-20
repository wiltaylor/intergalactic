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

use crate::packet::{self, PROTO_UDP};
use std::collections::HashMap;
use std::net::IpAddr;

pub const DNS_PORT: u16 = 53;
const TTL: u32 = 60;

#[derive(Default, Clone, Debug)]
pub struct DnsTable {
    /// lowercase fqdn (no trailing dot) -> addresses
    names: HashMap<String, Vec<IpAddr>>,
    reverse: HashMap<IpAddr, String>,
    /// Suffixes we are authoritative for (lowercase, no trailing dot).
    zones: Vec<String>,
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

    pub fn is_ours(&self, name: &str) -> bool {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        self.zones
            .iter()
            .any(|z| n == *z || n.ends_with(&format!(".{z}")))
            || n.ends_with(".in-addr.arpa")
            || n.ends_with(".ip6.arpa")
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

/// Build the IP/UDP reply packet for a query packet that arrived from the TUN.
pub fn reply_packet(table: &DnsTable, query_pkt: &[u8]) -> Option<Vec<u8>> {
    let flow = packet::parse_flow(query_pkt)?;
    if flow.proto != PROTO_UDP || flow.dport != DNS_PORT {
        return None;
    }
    let l4 = &query_pkt[flow.l4_offset..];
    if l4.len() < 8 {
        return None;
    }
    let udp_len = u16::from_be_bytes([l4[4], l4[5]]) as usize;
    let payload = l4.get(8..udp_len.min(l4.len()))?;
    let answer = respond(table, payload)?;
    Some(packet::build_udp(
        flow.dst, DNS_PORT, flow.src, flow.sport, &answer,
    ))
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
}
