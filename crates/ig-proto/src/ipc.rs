//! Local protocol between the `ig` CLI and the node daemon (`ig-node`).
//! JSON, newline-delimited, one request and one response per connection.

use crate::control::NetworkInfo;
use crate::{NetworkId, NodeId};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    Status,
    Join {
        invite: String,
    },
    Leave {
        network: String,
    },
    Peers,
    /// Request an ephemeral public port on the lighthouse for `target`.
    Expose {
        network: String,
        proto: crate::tunnel::ForwardProto,
        public_port: Option<u16>,
        target: String,
        label: String,
        /// Lighthouse name or host to publish on; default the first connected one.
        lighthouse: Option<String>,
    },
    Unexpose {
        id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok,
    Error { message: String },
    Status(StatusReport),
    Joined(NetworkInfo),
    Exposed(crate::tunnel::ForwardInfo),
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
    /// Primary lighthouse as host:port.
    pub lighthouse: String,
    pub lighthouse_connected: bool,
    /// Every lighthouse of the network and whether its control session is up.
    #[serde(default)]
    pub lighthouses: Vec<(String, bool)>,
    pub interface: Option<String>,
    /// False when the network is turned off on this device.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
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
    /// (network id, address in that network); both IPv4 and IPv6 entries.
    pub addresses: Vec<(NetworkId, IpAddr)>,
    /// (network id, fully qualified DNS name)
    #[serde(default)]
    pub names: Vec<(NetworkId, String)>,
    pub path: PeerPath,
    pub endpoint: Option<SocketAddr>,
    pub last_handshake_secs_ago: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}
