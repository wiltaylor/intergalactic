//! UDP datagrams exchanged with a lighthouse on the data-plane socket.
//!
//! WireGuard packets start with a message type byte 1..=4 followed by three zero
//! bytes. Disco frames start with the 4-byte magic `IGD\x01`, so a node can tell
//! the two apart from the first four bytes of a datagram.
//!
//! ```text
//! Probe       node -> LH   magic | 0x01 | node_id[32] | ts_be[8] | mac[16]
//! ProbeReply  LH -> node   magic | 0x02 | ts_be[8] | addr(postcard) | mac[16]
//! Relay       node -> LH   magic | 0x03 | dst_node[32] | wireguard payload
//! Relayed     LH -> node   magic | 0x04 | src_node[32] | wireguard payload
//! ```
//!
//! `mac` is the first 16 bytes of `blake3::keyed_hash(session_token, everything
//! before the mac)`. The session token is given to the node on its control
//! channel, so only the lighthouse and the node can produce or verify it.

use crate::NodeId;
use std::net::SocketAddr;

pub const MAGIC: [u8; 4] = *b"IGD\x01";
pub const RELAY_HEADER_LEN: usize = 4 + 1 + 32;

const T_PROBE: u8 = 1;
const T_PROBE_REPLY: u8 = 2;
const T_RELAY: u8 = 3;
const T_RELAYED: u8 = 4;
const MAC_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Disco<'a> {
    Probe { node: NodeId, ts: u64 },
    ProbeReply { ts: u64, observed: SocketAddr },
    Relay { dst: NodeId, payload: &'a [u8] },
    Relayed { src: NodeId, payload: &'a [u8] },
}

/// True if the datagram is a disco frame rather than WireGuard.
pub fn is_disco(datagram: &[u8]) -> bool {
    datagram.len() >= 5 && datagram[..4] == MAGIC
}

fn mac(key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    let h = blake3::keyed_hash(key, data);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&h.as_bytes()[..MAC_LEN]);
    out
}

pub fn encode_probe(node: &NodeId, ts: u64, session_token: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 32 + 8 + MAC_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(T_PROBE);
    out.extend_from_slice(&node.0);
    out.extend_from_slice(&ts.to_be_bytes());
    let m = mac(session_token, &out);
    out.extend_from_slice(&m);
    out
}

pub fn encode_probe_reply(ts: u64, observed: SocketAddr, session_token: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&MAGIC);
    out.push(T_PROBE_REPLY);
    out.extend_from_slice(&ts.to_be_bytes());
    out = postcard::to_extend(&observed, out).expect("socketaddr serializes");
    let m = mac(session_token, &out);
    out.extend_from_slice(&m);
    out
}

pub fn encode_relay(dst: &NodeId, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RELAY_HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(T_RELAY);
    out.extend_from_slice(&dst.0);
    out.extend_from_slice(payload);
    out
}

pub fn encode_relayed(src: &NodeId, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RELAY_HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(T_RELAYED);
    out.extend_from_slice(&src.0);
    out.extend_from_slice(payload);
    out
}

/// Parse without verifying MACs. Call [`verify_probe`] / [`verify_probe_reply`]
/// once the session token for the sender is known.
pub fn decode(datagram: &[u8]) -> Option<Disco<'_>> {
    if !is_disco(datagram) {
        return None;
    }
    let body = &datagram[5..];
    match datagram[4] {
        T_PROBE => {
            if body.len() != 32 + 8 + MAC_LEN {
                return None;
            }
            let node = NodeId(body[..32].try_into().ok()?);
            let ts = u64::from_be_bytes(body[32..40].try_into().ok()?);
            Some(Disco::Probe { node, ts })
        }
        T_PROBE_REPLY => {
            if body.len() < 8 + MAC_LEN + 1 {
                return None;
            }
            let ts = u64::from_be_bytes(body[..8].try_into().ok()?);
            let addr_bytes = &body[8..body.len() - MAC_LEN];
            let observed: SocketAddr = postcard::from_bytes(addr_bytes).ok()?;
            Some(Disco::ProbeReply { ts, observed })
        }
        T_RELAY => {
            if body.len() < 32 {
                return None;
            }
            Some(Disco::Relay { dst: NodeId(body[..32].try_into().ok()?), payload: &body[32..] })
        }
        T_RELAYED => {
            if body.len() < 32 {
                return None;
            }
            Some(Disco::Relayed { src: NodeId(body[..32].try_into().ok()?), payload: &body[32..] })
        }
        _ => None,
    }
}

/// Constant-time MAC check for a Probe or ProbeReply datagram.
pub fn verify_mac(datagram: &[u8], session_token: &[u8; 32]) -> bool {
    if datagram.len() < MAC_LEN + 5 {
        return false;
    }
    let (data, tag) = datagram.split_at(datagram.len() - MAC_LEN);
    let expected = mac(session_token, data);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_roundtrip_and_mac() {
        let node = NodeId(crate::random_array());
        let key = crate::random_array();
        let p = encode_probe(&node, 42, &key);
        assert!(is_disco(&p));
        assert_eq!(decode(&p), Some(Disco::Probe { node, ts: 42 }));
        assert!(verify_mac(&p, &key));
        assert!(!verify_mac(&p, &crate::random_array()));
    }

    #[test]
    fn probe_reply_roundtrip() {
        let key = crate::random_array();
        let addr: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        let r = encode_probe_reply(7, addr, &key);
        assert_eq!(decode(&r), Some(Disco::ProbeReply { ts: 7, observed: addr }));
        assert!(verify_mac(&r, &key));
        let addr6: SocketAddr = "[2001:db8::1]:1".parse().unwrap();
        let r6 = encode_probe_reply(1, addr6, &key);
        assert_eq!(decode(&r6), Some(Disco::ProbeReply { ts: 1, observed: addr6 }));
    }

    #[test]
    fn relay_frames() {
        let a = NodeId(crate::random_array());
        let f = encode_relay(&a, b"wg");
        assert_eq!(decode(&f), Some(Disco::Relay { dst: a, payload: b"wg" }));
        let g = encode_relayed(&a, b"wg");
        assert_eq!(decode(&g), Some(Disco::Relayed { src: a, payload: b"wg" }));
        assert!(!is_disco(&[4, 0, 0, 0, 1, 2, 3]));
    }
}
