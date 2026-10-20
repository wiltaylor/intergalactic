//! Local admin protocol for the lighthouse (`ig-lighthouse` CLI <-> daemon).
//! JSON, one request and one response per connection.

use crate::{NetworkId, NodeId, Policy, RelayLimit};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AdminRequest {
    Info,
    NetworkCreate {
        name: String,
        cidr: Ipv4Net,
        cidr6: Option<Ipv6Net>,
    },
    NetworkList,
    NetworkDelete {
        network: String,
    },
    NetworkSetPolicy {
        network: String,
        policy: Policy,
    },
    NetworkSetRelayLimit {
        network: String,
        limit: RelayLimit,
    },
    InviteCreate {
        network: String,
        uses: u32,
        ttl_secs: u64,
        label: String,
    },
    InviteList {
        network: String,
    },
    InviteRevoke {
        network: String,
        invite_id: String,
    },
    NodeList {
        network: Option<String>,
    },
    /// Register a device reachable through gateway nodes. `gateways` orders the
    /// preferred nodes; empty means any gateway-capable node on the device's LAN.
    DeviceAdd {
        network: String,
        name: String,
        target: Ipv4Addr,
        target6: Option<Ipv6Addr>,
        gateways: Vec<NodeId>,
    },
    DeviceList {
        network: String,
    },
    DeviceRemove {
        network: String,
        name: String,
    },
    /// Permanent forward: public port on a lighthouse -> overlay target of `node`.
    ForwardAdd {
        network: String,
        node: NodeId,
        proto: crate::tunnel::ForwardProto,
        public_port: u16,
        /// `self:PORT`, `<device>:PORT` or `<overlay ip>:PORT`.
        target: String,
        label: String,
        /// Which lighthouse publishes the port; default the primary.
        lighthouse: Option<NodeId>,
    },
    /// Register a replica lighthouse. It becomes a member of every network and
    /// may connect to replicate the store.
    LighthouseAdd {
        name: String,
        host: String,
        port: u16,
        key: NodeId,
    },
    LighthouseList,
    LighthouseRemove {
        key: NodeId,
    },
    ForwardList,
    ForwardRemove {
        id: String,
    },
    /// Allow or deny ephemeral forwards for a network.
    NetworkSetExposes {
        network: String,
        allowed: bool,
    },
    NodeRemove {
        network: String,
        node: NodeId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AdminResponse {
    Ok,
    Error { message: String },
    Info(LighthouseInfo),
    Networks(Vec<NetworkSummary>),
    Invite { invite: String, invite_id: String },
    Invites(Vec<InviteSummary>),
    Nodes(Vec<NodeSummary>),
    Devices(Vec<DeviceSummary>),
    Forwards(Vec<ForwardSummary>),
    Lighthouses(Vec<LighthouseSummary>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LighthouseSummary {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub key: NodeId,
    pub primary: bool,
    /// For replicas as seen from the primary: is the replication link up.
    pub connected: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardSummary {
    pub info: crate::tunnel::ForwardInfo,
    pub network_name: String,
    pub node_hostname: String,
    pub node_online: bool,
    pub lighthouse_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub network: NetworkId,
    pub network_name: String,
    pub name: String,
    pub dns_name: String,
    pub address: Ipv4Addr,
    pub target: Ipv4Addr,
    pub address6: Option<Ipv6Addr>,
    pub target6: Option<Ipv6Addr>,
    /// Preferred gateways in order; empty = automatic.
    pub gateways: Vec<NodeId>,
    /// Currently active gateway and its hostname.
    pub active: Option<(NodeId, String)>,
    /// Online gateway-capable nodes that could serve this device right now.
    pub candidates: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LighthouseInfo {
    pub public_key: NodeId,
    pub public_host: String,
    pub port: u16,
    pub networks: usize,
    pub nodes_online: usize,
    pub uptime_secs: u64,
    pub dns_domain: String,
    /// `primary` or `replica of <host:port>`.
    pub role: String,
    /// This lighthouse's overlay addresses, one per network, if it runs the overlay.
    pub overlay: Vec<(String, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub id: NetworkId,
    pub name: String,
    pub cidr: Ipv4Net,
    pub cidr6: Option<Ipv6Net>,
    pub members: usize,
    pub online: usize,
    pub policy: Policy,
    pub relay_limit: RelayLimit,
    pub exposes_allowed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteSummary {
    pub id: String,
    pub label: String,
    pub uses_left: u32,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSummary {
    pub node: NodeId,
    pub hostname: String,
    pub os: String,
    pub network: NetworkId,
    pub network_name: String,
    pub dns_name: String,
    pub address: Ipv4Addr,
    pub address6: Option<Ipv6Addr>,
    pub online: bool,
    pub endpoints: Vec<SocketAddr>,
    pub last_seen_secs_ago: Option<u64>,
}
