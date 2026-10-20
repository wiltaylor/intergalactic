//! Durable state the embedder persists for the engine.

use ig_proto::control::NetworkInfo;
use ig_proto::NodeId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Where a lighthouse lives and which key it must present.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LighthouseAddr {
    pub host: String,
    pub port: u16,
    pub key: NodeId,
}

impl LighthouseAddr {
    pub fn from_invite(inv: &ig_proto::Invite) -> Self {
        LighthouseAddr { host: inv.host.clone(), port: inv.port, key: inv.lighthouse }
    }

    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl fmt::Display for LighthouseAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} ({})", self.host, self.port, self.key.short())
    }
}

/// One joined network. The engine resumes these on start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub lighthouse: LighthouseAddr,
    pub network: NetworkInfo,
}
