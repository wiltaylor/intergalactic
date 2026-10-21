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

    /// Every lighthouse an invite names, the inviting one first.
    pub fn all_from_invite(inv: &ig_proto::Invite) -> Vec<Self> {
        let mut v = vec![Self::from_invite(inv)];
        for r in &inv.extra_lighthouses {
            let a = Self::from_ref(r);
            if !v.contains(&a) {
                v.push(a);
            }
        }
        v
    }

    pub fn from_ref(r: &ig_proto::control::LighthouseRef) -> Self {
        LighthouseAddr {
            host: r.host.clone(),
            port: r.port,
            key: r.key,
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
    /// Primary lighthouse.
    pub lighthouse: LighthouseAddr,
    /// Replica lighthouses that also serve the network.
    #[serde(default)]
    pub extra_lighthouses: Vec<LighthouseAddr>,
    pub network: NetworkInfo,
    /// Off: the membership and address are kept, but this device takes no part
    /// in the network until it is turned on again (no interface, no traffic).
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Membership {
    /// All lighthouses of the network, the one we joined through first.
    pub fn lighthouses(&self) -> Vec<LighthouseAddr> {
        let mut v = vec![self.lighthouse.clone()];
        for l in &self.extra_lighthouses {
            if !v.contains(l) {
                v.push(l.clone());
            }
        }
        v
    }

    pub fn has_lighthouse(&self, lh: &LighthouseAddr) -> bool {
        self.lighthouse == *lh || self.extra_lighthouses.contains(lh)
    }

    /// Replace the lighthouse list with what the lighthouse reports in the
    /// network info (keeps the primary first).
    pub fn sync_lighthouses_from_info(&mut self) {
        let refs: Vec<LighthouseAddr> = self
            .network
            .lighthouses
            .iter()
            .map(LighthouseAddr::from_ref)
            .collect();
        if refs.is_empty() {
            return;
        }
        if refs.contains(&self.lighthouse) {
            self.extra_lighthouses = refs.into_iter().filter(|l| *l != self.lighthouse).collect();
        } else {
            // Our primary is no longer listed; adopt the reported primary.
            let mut it = refs.into_iter();
            self.lighthouse = it.next().expect("non-empty");
            self.extra_lighthouses = it.collect();
        }
    }
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
