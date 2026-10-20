//! Local admin protocol for the lighthouse (`ig-lighthouse` CLI <-> daemon).
//! JSON, one request and one response per connection.

use crate::{NetworkId, NodeId, Policy};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AdminRequest {
    Info,
    NetworkCreate {
        name: String,
        cidr: Ipv4Net,
    },
    NetworkList,
    NetworkDelete {
        network: String,
    },
    NetworkSetPolicy {
        network: String,
        policy: Policy,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LighthouseInfo {
    pub public_key: NodeId,
    pub public_host: String,
    pub port: u16,
    pub networks: usize,
    pub nodes_online: usize,
    pub uptime_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub id: NetworkId,
    pub name: String,
    pub cidr: Ipv4Net,
    pub members: usize,
    pub online: usize,
    pub policy: Policy,
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
    pub address: Ipv4Addr,
    pub online: bool,
    pub endpoints: Vec<SocketAddr>,
    pub last_seen_secs_ago: Option<u64>,
}
