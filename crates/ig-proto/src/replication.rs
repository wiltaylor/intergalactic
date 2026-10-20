//! Primary/replica replication between lighthouses.
//!
//! One lighthouse is the **primary** and owns the store. Replicas connect to it
//! over Noise (their hello sets `replica = true`), receive a full snapshot on
//! connect and after every change, and serve nodes from that copy. Writes a
//! replica receives from nodes (joins, leaves) are proxied to the primary.

use crate::control::{FromLighthouse, ToLighthouse};
use crate::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ToPrimary {
    /// A node connected to the replica asked for something only the primary
    /// may decide. `hostname`/`os` let the primary record the node.
    Proxy {
        node: NodeId,
        hostname: String,
        os: String,
        msg: ToLighthouse,
    },
    Ping,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum FromPrimary {
    /// The whole store as JSON. Small (members, invites, devices, forwards).
    Snapshot {
        store_json: Vec<u8>,
    },
    /// Answer to a proxied request, to be relayed to that node.
    ProxyReply {
        node: NodeId,
        msg: FromLighthouse,
    },
    Pong,
}
