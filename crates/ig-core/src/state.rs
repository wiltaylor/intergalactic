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
        LighthouseAddr {
            host: inv.host.clone(),
            port: inv.port,
            key: inv.lighthouse,
        }
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

/// Everything a node must keep across restarts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeState {
    pub private_key: ig_proto::PrivateKey,
    #[serde(default)]
    pub memberships: Vec<Membership>,
}

impl NodeState {
    pub fn generate() -> Self {
        NodeState {
            private_key: ig_proto::PrivateKey::generate(),
            memberships: Vec::new(),
        }
    }

    pub fn load(path: &std::path::Path) -> std::io::Result<Option<NodeState>> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, path)
    }
}
