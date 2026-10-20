//! Persistent state: networks, members, invites. Stored as one JSON document
//! that is rewritten atomically after every change. Changes are rare (joins,
//! invites, admin edits), so this is simpler and more robust than a database.

use ig_proto::{NetworkId, NodeId, Policy};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub networks: BTreeMap<NetworkId, Network>,
    #[serde(default)]
    pub nodes: BTreeMap<NodeId, NodeRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    pub id: NetworkId,
    pub name: String,
    pub cidr: Ipv4Net,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub members: BTreeMap<NodeId, Member>,
    #[serde(default)]
    pub invites: Vec<InviteRecord>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub address: Ipv4Addr,
    pub joined_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteRecord {
    pub id: String,
    pub label: String,
    #[serde(with = "hex32")]
    pub token_hash: [u8; 32],
    pub uses_left: u32,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeRecord {
    pub hostname: String,
    pub os: String,
    pub last_seen: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("network not found: {0}")]
    NoSuchNetwork(String),
    #[error("a network named `{0}` already exists")]
    DuplicateName(String),
    #[error("prefix /{0} is too small; use /30 or larger")]
    PrefixTooSmall(u8),
    #[error("network is full")]
    Full,
    #[error("invite is invalid, expired or used up")]
    BadInvite,
    #[error("invite not found: {0}")]
    NoSuchInvite(String),
    #[error("node is not a member")]
    NotMember,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

impl Network {
    fn host_range(&self) -> (u32, u32) {
        let base = u32::from(self.cidr.network());
        let bcast = u32::from(self.cidr.broadcast());
        // Reserve network address and broadcast; /31 and /32 are refused at creation.
        (base + 1, bcast - 1)
    }

    pub fn capacity(&self) -> u32 {
        let (lo, hi) = self.host_range();
        hi - lo + 1
    }

    fn allocate(&self) -> Option<Ipv4Addr> {
        let (lo, hi) = self.host_range();
        let used: std::collections::HashSet<u32> = self
            .members
            .values()
            .map(|m| u32::from(m.address))
            .collect();
        (lo..=hi).find(|a| !used.contains(a)).map(Ipv4Addr::from)
    }

    pub fn find_invite(&self, token: &[u8; 16]) -> Option<usize> {
        let hash = ig_proto::Invite::token_hash(token);
        let now = now_secs();
        self.invites
            .iter()
            .position(|i| i.token_hash == hash && i.uses_left > 0 && i.expires_at > now)
    }
}

impl Store {
    pub fn load(path: &Path) -> Result<Store, StoreError> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp: PathBuf = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Find a network by id (hex) or by name.
    pub fn resolve(&self, name_or_id: &str) -> Result<NetworkId, StoreError> {
        if let Ok(id) = name_or_id.parse::<NetworkId>() {
            if self.networks.contains_key(&id) {
                return Ok(id);
            }
        }
        self.networks
            .values()
            .find(|n| n.name == name_or_id)
            .map(|n| n.id)
            .ok_or_else(|| StoreError::NoSuchNetwork(name_or_id.to_string()))
    }

    pub fn create_network(&mut self, name: &str, cidr: Ipv4Net) -> Result<&Network, StoreError> {
        if self.networks.values().any(|n| n.name == name) {
            return Err(StoreError::DuplicateName(name.to_string()));
        }
        if cidr.prefix_len() > 30 {
            return Err(StoreError::PrefixTooSmall(cidr.prefix_len()));
        }
        let id = NetworkId::random();
        let net = Network {
            id,
            name: name.to_string(),
            cidr: cidr.trunc(),
            policy: Policy::allow_all(),
            members: BTreeMap::new(),
            invites: Vec::new(),
            created_at: now_secs(),
        };
        self.networks.insert(id, net);
        Ok(&self.networks[&id])
    }

    /// Consume an invite and add the node. Re-joining an existing member returns
    /// the existing address without consuming the invite.
    pub fn join(
        &mut self,
        network: NetworkId,
        node: NodeId,
        token: &[u8; 16],
    ) -> Result<Ipv4Addr, StoreError> {
        let net = self
            .networks
            .get_mut(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        if let Some(m) = net.members.get(&node) {
            return Ok(m.address);
        }
        let idx = net.find_invite(token).ok_or(StoreError::BadInvite)?;
        let address = net.allocate().ok_or(StoreError::Full)?;
        net.invites[idx].uses_left -= 1;
        if net.invites[idx].uses_left == 0 {
            net.invites.remove(idx);
        }
        net.members.insert(
            node,
            Member {
                address,
                joined_at: now_secs(),
            },
        );
        Ok(address)
    }

    pub fn remove_member(&mut self, network: NetworkId, node: &NodeId) -> Result<(), StoreError> {
        let net = self
            .networks
            .get_mut(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        net.members
            .remove(node)
            .map(|_| ())
            .ok_or(StoreError::NotMember)
    }

    pub fn networks_of(&self, node: &NodeId) -> Vec<NetworkId> {
        self.networks
            .values()
            .filter(|n| n.members.contains_key(node))
            .map(|n| n.id)
            .collect()
    }

    pub fn share_network(&self, a: &NodeId, b: &NodeId) -> bool {
        self.networks
            .values()
            .any(|n| n.members.contains_key(a) && n.members.contains_key(b))
    }

    pub fn touch_node(&mut self, node: NodeId, hostname: &str, os: &str) {
        let rec = self.nodes.entry(node).or_default();
        rec.hostname = hostname.to_string();
        rec.os = os.to_string();
        rec.last_seen = now_secs();
    }

    /// Drop expired invites. Returns true if anything changed.
    pub fn prune_invites(&mut self) -> bool {
        let now = now_secs();
        let mut changed = false;
        for n in self.networks.values_mut() {
            let before = n.invites.len();
            n.invites.retain(|i| i.expires_at > now && i.uses_left > 0);
            changed |= n.invites.len() != before;
        }
        changed
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
        hex.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(D::Error::custom("expected 64 hex chars"));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let h = std::str::from_utf8(chunk).map_err(D::Error::custom)?;
            out[i] = u8::from_str_radix(h, 16).map_err(D::Error::custom)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite(net: &mut Network, uses: u32) -> [u8; 16] {
        let token: [u8; 16] = ig_proto::random_array();
        net.invites.push(InviteRecord {
            id: "abc".into(),
            label: String::new(),
            token_hash: ig_proto::Invite::token_hash(&token),
            uses_left: uses,
            expires_at: now_secs() + 3600,
        });
        token
    }

    #[test]
    fn join_allocates_sequential_addresses_and_consumes_invites() {
        let mut s = Store::default();
        let id = s
            .create_network("dev", "10.90.0.0/29".parse().unwrap())
            .unwrap()
            .id;
        let token = invite(s.networks.get_mut(&id).unwrap(), 2);
        let a = NodeId(ig_proto::random_array());
        let b = NodeId(ig_proto::random_array());
        let c = NodeId(ig_proto::random_array());
        assert_eq!(
            s.join(id, a, &token).unwrap(),
            "10.90.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            s.join(id, b, &token).unwrap(),
            "10.90.0.2".parse::<Ipv4Addr>().unwrap()
        );
        // Used up.
        assert!(matches!(s.join(id, c, &token), Err(StoreError::BadInvite)));
        // Re-join is idempotent and needs no invite.
        assert_eq!(
            s.join(id, a, &[0u8; 16]).unwrap(),
            "10.90.0.1".parse::<Ipv4Addr>().unwrap()
        );
        s.remove_member(id, &a).unwrap();
        let token2 = invite(s.networks.get_mut(&id).unwrap(), 10);
        // Freed address is reused.
        assert_eq!(
            s.join(id, c, &token2).unwrap(),
            "10.90.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert!(s.share_network(&b, &c));
        assert!(!s.share_network(&a, &b));
    }

    #[test]
    fn rejects_bad_networks() {
        let mut s = Store::default();
        s.create_network("x", "10.0.0.0/24".parse().unwrap())
            .unwrap();
        assert!(matches!(
            s.create_network("x", "10.1.0.0/24".parse().unwrap()),
            Err(StoreError::DuplicateName(_))
        ));
        assert!(matches!(
            s.create_network("y", "10.1.0.0/31".parse().unwrap()),
            Err(StoreError::PrefixTooSmall(31))
        ));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ig-store-test-{}", std::process::id()));
        let path = dir.join("lighthouse.json");
        let mut s = Store::default();
        let id = s
            .create_network("dev", "10.90.0.0/24".parse().unwrap())
            .unwrap()
            .id;
        invite(s.networks.get_mut(&id).unwrap(), 1);
        s.save(&path).unwrap();
        let back = Store::load(&path).unwrap();
        assert_eq!(back.networks[&id].invites.len(), 1);
        assert_eq!(
            back.networks[&id].invites[0].token_hash,
            s.networks[&id].invites[0].token_hash
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
