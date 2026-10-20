//! Control channel messages (node <-> lighthouse) carried inside the Noise
//! transport described in [`crate::noise`]. Encoded with postcard.

use crate::{NetworkId, NodeId, Policy};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

/// Payload of the first Noise handshake message (node -> lighthouse).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u16,
    pub hostname: String,
    /// Free-form OS tag ("linux", "windows", "android").
    pub os: String,
}

/// Payload of the second Noise handshake message (lighthouse -> node).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u16,
    /// Secret shared for the lifetime of this control session. Authenticates the
    /// node's UDP disco probes so nobody can poison its reflexive address.
    pub session_token: [u8; 32],
    /// Unix time in seconds on the lighthouse, for clock-skew diagnostics only.
    pub server_time: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ToLighthouse {
    /// Join a network using an invite token. The lighthouse replies with
    /// `Joined` or `JoinFailed` carrying the same network id.
    Join { network: NetworkId, token: [u8; 16] },
    /// Leave a network. Membership and address are released.
    Leave { network: NetworkId },
    /// Ask for the state of every network this node is already a member of.
    /// Sent once after every (re)connect.
    Resume,
    /// Local candidate endpoints (LAN addresses + UDP port). The lighthouse adds
    /// the reflexive address it observes on UDP and shares the union with peers.
    Endpoints { local: Vec<SocketAddr> },
    /// Ask the lighthouse to tell `target` to start sending towards us so both
    /// NATs open at the same time.
    Punch { network: NetworkId, target: NodeId },
    Ping { nonce: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FromLighthouse {
    Joined { network: NetworkInfo },
    JoinFailed { network: NetworkId, reason: String },
    Left { network: NetworkId },
    /// Full membership of one network. Sent after join/resume and whenever
    /// anything about the network or its members changes.
    NetworkState { network: NetworkInfo, peers: Vec<PeerInfo> },
    /// The node was removed from the network by an admin or the network was deleted.
    Removed { network: NetworkId, reason: String },
    /// A peer wants to reach us; start sending towards its endpoints now.
    PunchRequest { network: NetworkId, from: NodeId, endpoints: Vec<SocketAddr> },
    Pong { nonce: u64 },
    Error { message: String },
}

/// What a member knows about a network it belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub id: NetworkId,
    pub name: String,
    pub cidr: Ipv4Net,
    /// This node's address inside `cidr`.
    pub address: Ipv4Addr,
    pub policy: Policy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node: NodeId,
    pub hostname: String,
    pub address: Ipv4Addr,
    /// Candidate endpoints: LAN addresses as reported by the peer plus the public
    /// address the lighthouse observed. Try all; keep the one that answers.
    pub endpoints: Vec<SocketAddr>,
    /// True while the peer holds a control session with the lighthouse.
    pub online: bool,
}
