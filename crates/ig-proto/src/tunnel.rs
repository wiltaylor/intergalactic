//! Port forwarding through the lighthouse.
//!
//! The lighthouse has the public address. A **forward** binds one public port on
//! it to a target a node can reach (`127.0.0.1:8080` on the node itself, or any
//! `host:port` behind it). Permanent forwards are created by the admin and
//! persisted; ephemeral forwards are requested by a node and live as long as its
//! session.
//!
//! Bytes travel over the node's **tunnel channel**: a second Noise/TCP
//! connection to the lighthouse whose hello sets `tunnel = true`. The lighthouse
//! opens one stream per public TCP connection (or per remote UDP peer) and both
//! sides exchange [`TunnelMsg`] frames.

use crate::{NetworkId, NodeId};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ForwardProto {
    Tcp,
    Udp,
}

impl fmt::Display for ForwardProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ForwardProto::Tcp => "tcp",
            ForwardProto::Udp => "udp",
        })
    }
}

impl std::str::FromStr for ForwardProto {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(ForwardProto::Tcp),
            "udp" => Ok(ForwardProto::Udp),
            other => Err(format!("unknown protocol `{other}`; use tcp or udp")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwardKind {
    /// Created by the admin, persisted, independent of sessions.
    Permanent,
    /// Requested by the node, gone when its session ends.
    Ephemeral,
}

/// Everything a node (and `ig exposes`) needs to know about a forward that
/// points at it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardInfo {
    pub id: String,
    pub network: NetworkId,
    pub node: NodeId,
    pub proto: ForwardProto,
    pub kind: ForwardKind,
    /// Where the internet connects: the lighthouse's public host and this port.
    pub public_host: String,
    pub public_port: u16,
    /// Where the node connects for each stream, e.g. `127.0.0.1:8080`.
    pub target: String,
    pub label: String,
}

/// Frames on the tunnel channel, in both directions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TunnelMsg {
    /// Lighthouse -> node: a public client connected (TCP) or sent its first
    /// datagram (UDP). The node connects to `target` and answers with data or
    /// with `Close`.
    Open {
        stream: u32,
        forward: String,
        proto: ForwardProto,
        target: String,
        remote: SocketAddr,
    },
    Data {
        stream: u32,
        data: Vec<u8>,
    },
    Close {
        stream: u32,
        reason: String,
    },
    /// Keepalive in either direction.
    Ping,
}

/// Largest payload in one `Data` frame.
pub const CHUNK: usize = 16 * 1024;
