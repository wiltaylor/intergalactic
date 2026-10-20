//! Local protocol between the `ig` CLI and the node daemon (`ig-node`).
//! JSON, newline-delimited, one request and one response per connection.

use crate::control::NetworkInfo;
use crate::{NetworkId, NodeId};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    Status,
    Join { invite: String },
    Leave { network: String },
    Peers,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok,
    Error { message: String },
    Status(StatusReport),
    Joined(NetworkInfo),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatusReport {
    pub node: Option<NodeId>,
    pub hostname: String,
    pub udp_port: u16,
    pub networks: Vec<NetworkStatus>,
    pub peers: Vec<PeerStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub info: NetworkInfo,
    pub lighthouse: String,
    pub lighthouse_connected: bool,
    pub interface: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerPath {
    /// No session yet.
    None,
    /// Traffic flows peer-to-peer.
    Direct,
    /// Traffic is relayed through the lighthouse.
    Relay,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub node: NodeId,
    pub hostname: String,
    pub online: bool,
    /// (network id, address in that network)
    pub addresses: Vec<(NetworkId, Ipv4Addr)>,
    pub path: PeerPath,
    pub endpoint: Option<SocketAddr>,
    pub last_handshake_secs_ago: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}
