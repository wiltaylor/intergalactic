//! Public port forwards. The lighthouse has the public address and is itself a
//! member of every network it serves, so a forward is a kernel NAT rule on the
//! lighthouse: public port -> an overlay address and port, carried to the node
//! over WireGuard like any other overlay traffic. Permanent forwards are created
//! by the admin and persisted; ephemeral forwards are requested by a node and
//! live as long as its session with that lighthouse.

use crate::{NetworkId, NodeId};
use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// Requested by the node, gone when its session with the lighthouse ends.
    Ephemeral,
}

/// A forward as nodes and admins see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardInfo {
    pub id: String,
    pub network: NetworkId,
    /// Member the traffic is for.
    pub node: NodeId,
    /// Lighthouse that publishes the port.
    pub lighthouse: NodeId,
    pub proto: ForwardProto,
    pub kind: ForwardKind,
    pub public_host: String,
    pub public_port: u16,
    /// Overlay target: `self:PORT` for the node's own address, `<device>:PORT`
    /// for a registered gateway device, or `<overlay ip>:PORT`.
    pub target: String,
    pub label: String,
}
