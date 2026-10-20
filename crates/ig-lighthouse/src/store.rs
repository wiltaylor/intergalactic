//! Persistent state: networks, members, invites. Stored as one JSON document
//! that is rewritten atomically after every change. Changes are rare (joins,
//! invites, admin edits), so this is simpler and more robust than a database.

use ig_proto::control::dns_label;
use ig_proto::{NetworkId, NodeId, Policy, RelayLimit};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn default_true() -> bool {
    true
}

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
    /// Permanent public port forwards, by id.
    #[serde(default)]
    pub forwards: BTreeMap<String, ForwardRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardRecord {
    pub id: String,
    pub network: NetworkId,
    pub node: NodeId,
    pub proto: ig_proto::tunnel::ForwardProto,
    pub public_port: u16,
    pub target: String,
    #[serde(default)]
    pub label: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    pub id: NetworkId,
    pub name: String,
    pub cidr: Ipv4Net,
    #[serde(default)]
    pub cidr6: Option<Ipv6Net>,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub relay_limit: RelayLimit,
    /// Members may request ephemeral public port forwards.
    #[serde(default = "default_true")]
    pub exposes_allowed: bool,
    #[serde(default)]
    pub members: BTreeMap<NodeId, Member>,
    #[serde(default)]
    pub invites: Vec<InviteRecord>,
    /// Devices on physical LANs reachable through gateway members, by name.
    #[serde(default)]
    pub devices: BTreeMap<String, Device>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub dns_name: String,
    /// Overlay address, allocated from the network like a member's.
    pub address: Ipv4Addr,
    /// Physical address on the gateways' LAN.
    pub target: Ipv4Addr,
    /// IPv6 overlay address (same host number as `address`) and physical address.
    #[serde(default)]
    pub address6: Option<Ipv6Addr>,
    #[serde(default)]
    pub target6: Option<Ipv6Addr>,
    /// Preferred gateways in order. Empty: any gateway-capable member whose LAN
    /// contains `target`.
    #[serde(default)]
    pub gateways: Vec<NodeId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub address: Ipv4Addr,
    #[serde(default)]
    pub address6: Option<Ipv6Addr>,
    /// Unique DNS label within the network.
    #[serde(default)]
    pub dns_name: String,
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
    #[error("IPv6 prefix /{0} is too small; use /120 or larger")]
    Prefix6TooSmall(u8),
    #[error("network is full")]
    Full,
    #[error("invite is invalid, expired or used up")]
    BadInvite,
    #[error("invite not found: {0}")]
    NoSuchInvite(String),
    #[error("node is not a member")]
    NotMember,
    #[error("a device named `{0}` already exists in this network")]
    DuplicateDevice(String),
    #[error("device not found: {0}")]
    NoSuchDevice(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

impl Network {
    fn host_range(&self) -> (u32, u32) {
        let base = u32::from(self.cidr.network());
        let bcast = u32::from(self.cidr.broadcast());
        // Reserve the network address, the first host (DNS responder) and the
        // broadcast address; /31 and /32 are refused at creation.
        (base + 2, bcast - 1)
    }

    /// IPv6 address with the same host offset as the IPv4 address, so a member's
    /// two addresses line up (`10.90.0.7` and `fd..::7`).
    fn address6_for(&self, v4: Ipv4Addr) -> Option<Ipv6Addr> {
        let cidr6 = self.cidr6?;
        let offset = u32::from(v4) - u32::from(self.cidr.network());
        Some(Ipv6Addr::from(u128::from(cidr6.network()) + offset as u128))
    }

    /// Unique DNS label for a hostname within this network.
    fn unique_label(&self, hostname: &str) -> String {
        let base = dns_label(hostname);
        let taken: std::collections::HashSet<&str> = self
            .members
            .values()
            .map(|m| m.dns_name.as_str())
            .chain(self.devices.values().map(|d| d.dns_name.as_str()))
            .collect();
        if !taken.contains(base.as_str()) {
            return base;
        }
        for i in 2.. {
            let candidate = format!("{base}-{i}");
            if !taken.contains(candidate.as_str()) {
                return candidate;
            }
        }
        unreachable!()
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
            .chain(self.devices.values().map(|d| u32::from(d.address)))
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

    pub fn create_network(
        &mut self,
        name: &str,
        cidr: Ipv4Net,
        cidr6: Option<Ipv6Net>,
    ) -> Result<&Network, StoreError> {
        if self.networks.values().any(|n| n.name == name) {
            return Err(StoreError::DuplicateName(name.to_string()));
        }
        if cidr.prefix_len() > 30 {
            return Err(StoreError::PrefixTooSmall(cidr.prefix_len()));
        }
        if let Some(c6) = cidr6 {
            if c6.prefix_len() > 120 {
                return Err(StoreError::Prefix6TooSmall(c6.prefix_len()));
            }
        }
        let id = NetworkId::random();
        let net = Network {
            id,
            name: name.to_string(),
            cidr: cidr.trunc(),
            cidr6: cidr6.map(|c| c.trunc()),
            policy: Policy::allow_all(),
            relay_limit: RelayLimit::unlimited(),
            exposes_allowed: true,
            devices: BTreeMap::new(),
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
        let hostname = self
            .nodes
            .get(&node)
            .map(|n| n.hostname.clone())
            .unwrap_or_default();
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
        let address6 = net.address6_for(address);
        let dns_name = net.unique_label(&hostname);
        net.members.insert(
            node,
            Member {
                address,
                address6,
                dns_name,
                joined_at: now_secs(),
            },
        );
        Ok(address)
    }

    /// Refresh a member's DNS label after its hostname changed. Returns the
    /// networks whose state changed.
    pub fn refresh_labels(&mut self, node: &NodeId) -> Vec<NetworkId> {
        let hostname = self
            .nodes
            .get(node)
            .map(|n| n.hostname.clone())
            .unwrap_or_default();
        let base = dns_label(&hostname);
        let mut changed = Vec::new();
        for net in self.networks.values_mut() {
            let Some(current) = net.members.get(node).map(|m| m.dns_name.clone()) else {
                continue;
            };
            if current == base || current.starts_with(&format!("{base}-")) {
                continue;
            }
            let label = net.unique_label(&hostname);
            net.members.get_mut(node).expect("present").dns_name = label;
            changed.push(net.id);
        }
        changed
    }

    pub fn add_device(
        &mut self,
        network: NetworkId,
        name: &str,
        target: Ipv4Addr,
        target6: Option<Ipv6Addr>,
        gateways: Vec<NodeId>,
    ) -> Result<Device, StoreError> {
        let net = self
            .networks
            .get_mut(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        if net.devices.contains_key(name) {
            return Err(StoreError::DuplicateDevice(name.to_string()));
        }
        let address = net.allocate().ok_or(StoreError::Full)?;
        let dns_name = net.unique_label(name);
        let address6 = if target6.is_some() {
            net.address6_for(address)
        } else {
            None
        };
        let dev = Device {
            name: name.to_string(),
            dns_name,
            address,
            target,
            address6,
            target6,
            gateways,
        };
        net.devices.insert(name.to_string(), dev.clone());
        Ok(dev)
    }

    pub fn remove_device(&mut self, network: NetworkId, name: &str) -> Result<(), StoreError> {
        let net = self
            .networks
            .get_mut(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        net.devices
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| StoreError::NoSuchDevice(name.to_string()))
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
            .create_network(
                "dev",
                "10.90.0.0/29".parse().unwrap(),
                Some("fd42::/64".parse().unwrap()),
            )
            .unwrap()
            .id;
        let token = invite(s.networks.get_mut(&id).unwrap(), 2);
        let a = NodeId(ig_proto::random_array());
        let b = NodeId(ig_proto::random_array());
        let c = NodeId(ig_proto::random_array());
        s.touch_node(a, "Laptop", "linux");
        s.touch_node(b, "laptop", "windows");
        assert_eq!(
            s.join(id, a, &token).unwrap(),
            "10.90.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            s.join(id, b, &token).unwrap(),
            "10.90.0.3".parse::<Ipv4Addr>().unwrap()
        );
        let ma = &s.networks[&id].members[&a];
        assert_eq!(ma.address6, Some("fd42::2".parse().unwrap()));
        assert_eq!(ma.dns_name, "laptop");
        assert_eq!(s.networks[&id].members[&b].dns_name, "laptop-2");
        // Used up.
        assert!(matches!(s.join(id, c, &token), Err(StoreError::BadInvite)));
        // Re-join is idempotent and needs no invite.
        assert_eq!(
            s.join(id, a, &[0u8; 16]).unwrap(),
            "10.90.0.2".parse::<Ipv4Addr>().unwrap()
        );
        s.remove_member(id, &a).unwrap();
        let token2 = invite(s.networks.get_mut(&id).unwrap(), 10);
        // Freed address is reused.
        assert_eq!(
            s.join(id, c, &token2).unwrap(),
            "10.90.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert!(s.share_network(&b, &c));
        assert!(!s.share_network(&a, &b));
        // Devices take addresses from the same pool and unique labels.
        let d = s
            .add_device(
                id,
                "laptop",
                "192.168.1.9".parse().unwrap(),
                Some("fd70::9".parse().unwrap()),
                vec![],
            )
            .unwrap();
        assert_eq!(
            d.address6,
            Some("fd42::4".parse().unwrap()),
            "same host number as the IPv4 address"
        );
        assert_eq!(d.address, "10.90.0.4".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            d.dns_name, "laptop",
            "alpha left, so the base label is free again"
        );
        assert!(matches!(
            s.add_device(id, "laptop", "192.168.1.9".parse().unwrap(), None, vec![]),
            Err(StoreError::DuplicateDevice(_))
        ));
        s.remove_device(id, "laptop").unwrap();
    }

    #[test]
    fn rejects_bad_networks() {
        let mut s = Store::default();
        s.create_network("x", "10.0.0.0/24".parse().unwrap(), None)
            .unwrap();
        assert!(matches!(
            s.create_network("x", "10.1.0.0/24".parse().unwrap(), None),
            Err(StoreError::DuplicateName(_))
        ));
        assert!(matches!(
            s.create_network("y", "10.1.0.0/31".parse().unwrap(), None),
            Err(StoreError::PrefixTooSmall(31))
        ));
        assert!(matches!(
            s.create_network(
                "z",
                "10.2.0.0/24".parse().unwrap(),
                Some("fd00::/124".parse().unwrap())
            ),
            Err(StoreError::Prefix6TooSmall(124))
        ));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ig-store-test-{}", std::process::id()));
        let path = dir.join("lighthouse.json");
        let mut s = Store::default();
        let id = s
            .create_network("dev", "10.90.0.0/24".parse().unwrap(), None)
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
