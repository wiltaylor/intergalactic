//! Persistent, mergeable state: networks, members, devices, invites, forwards and
//! the lighthouses themselves. Stored as one JSON document that is rewritten
//! atomically after every change.
//!
//! There is no primary lighthouse. Every lighthouse writes its own copy and the
//! copies converge when they meet:
//!
//! - Every record carries a [`Version`] `(clock, lighthouse)`. Of two copies of
//!   the same record the greater version wins (last writer wins).
//! - A removal leaves a tombstone with its own version, so an older copy of the
//!   record cannot come back.
//! - Invites count their uses per lighthouse, so two lighthouses consuming the
//!   same invite add up instead of overwriting each other.
//! - Each lighthouse allocates addresses from its own slice of a network's pool,
//!   so concurrent joins almost never collide. After a merge, duplicates that
//!   slipped through (addresses, DNS labels, device targets) are resolved
//!   deterministically, so every lighthouse ends up with the same answer.

use ig_proto::control::dns_label;
use ig_proto::{NetworkId, NodeId, Policy, RelayLimit};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn default_true() -> bool {
    true
}

fn zero_id() -> NodeId {
    NodeId([0u8; 32])
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Logical timestamp of a record: a hybrid clock (milliseconds, never going
/// backwards) and the lighthouse that wrote it as the tie breaker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    pub ts: u64,
    pub by: NodeId,
}

impl Default for Version {
    fn default() -> Self {
        Version {
            ts: 0,
            by: zero_id(),
        }
    }
}

impl Version {
    /// The version a deterministic removal gets: just after the record itself.
    fn after(self) -> Version {
        Version {
            ts: self.ts + 1,
            by: self.by,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub networks: BTreeMap<NetworkId, Network>,
    #[serde(default)]
    pub nodes: BTreeMap<NodeId, NodeRecord>,
    /// Permanent public port forwards, by id.
    #[serde(default)]
    pub forwards: BTreeMap<String, ForwardRecord>,
    /// Every lighthouse serving these networks, this one included. Each is a
    /// member of every network.
    #[serde(default)]
    pub lighthouses: BTreeMap<NodeId, LighthouseRecord>,
    /// Removed records, by key (see `keys`), with the version of the removal.
    #[serde(default)]
    pub tombstones: BTreeMap<String, Version>,
    /// Hybrid logical clock: the greatest version timestamp seen or issued.
    #[serde(default)]
    pub clock: u64,
    /// This lighthouse. Not stored: set when the store is loaded.
    #[serde(skip, default = "zero_id")]
    me: NodeId,
}

impl Default for Store {
    fn default() -> Self {
        Store::new(zero_id())
    }
}

/// Equality of the replicated content: `me` and the clock are local.
impl PartialEq for Store {
    fn eq(&self, other: &Store) -> bool {
        self.networks == other.networks
            && self.nodes == other.nodes
            && self.forwards == other.forwards
            && self.lighthouses == other.lighthouses
            && self.tombstones == other.tombstones
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LighthouseRecord {
    pub key: NodeId,
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub version: Version,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ForwardRecord {
    pub id: String,
    pub network: NetworkId,
    pub node: NodeId,
    pub proto: ig_proto::tunnel::ForwardProto,
    pub public_port: u16,
    pub target: String,
    #[serde(default)]
    pub label: String,
    /// Lighthouse that publishes the port.
    pub lighthouse: NodeId,
    pub created_at: u64,
    #[serde(default)]
    pub version: Version,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    /// Invites by id.
    #[serde(default)]
    pub invites: BTreeMap<String, InviteRecord>,
    /// Devices on physical LANs reachable through gateway members, by name.
    #[serde(default)]
    pub devices: BTreeMap<String, Device>,
    pub created_at: u64,
    /// Version of the settings (name, prefixes, policy, limits, exposes).
    #[serde(default)]
    pub version: Version,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub version: Version,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Member {
    pub address: Ipv4Addr,
    #[serde(default)]
    pub address6: Option<Ipv6Addr>,
    /// Unique DNS label within the network.
    #[serde(default)]
    pub dns_name: String,
    pub joined_at: u64,
    #[serde(default)]
    pub version: Version,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteRecord {
    pub id: String,
    pub label: String,
    #[serde(with = "hex32")]
    pub token_hash: [u8; 32],
    /// How many joins the invite allows in total.
    pub uses: u32,
    /// Joins consumed, per lighthouse. Merges by taking the maximum per key.
    #[serde(default)]
    pub used: BTreeMap<NodeId, u32>,
    pub expires_at: u64,
    #[serde(default)]
    pub version: Version,
}

impl InviteRecord {
    pub fn used_total(&self) -> u32 {
        self.used.values().fold(0u32, |a, b| a.saturating_add(*b))
    }

    pub fn uses_left(&self) -> u32 {
        self.uses.saturating_sub(self.used_total())
    }

    fn usable(&self, now: u64) -> bool {
        self.uses_left() > 0 && self.expires_at > now
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub hostname: String,
    pub os: String,
    pub last_seen: u64,
}

/// What a merge changed.
#[derive(Debug, Default)]
pub struct MergeOutcome {
    pub changed: bool,
    /// Networks whose state differs from before (including removed ones).
    pub networks: Vec<NetworkId>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("network not found: {0}")]
    NoSuchNetwork(String),
    #[error("`{0}` names {1} networks (created on different lighthouses); use the id")]
    AmbiguousName(String, usize),
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
    #[error("lighthouse not found: {0}")]
    NoSuchLighthouse(String),
    #[error("a lighthouse with that key is already registered")]
    DuplicateLighthouse,
    #[error("device not found: {0}")]
    NoSuchDevice(String),
    #[error("device `{0}` already has that physical address in this network")]
    DuplicateTarget(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

/// Tombstone keys.
mod keys {
    use ig_proto::{NetworkId, NodeId};

    pub fn network(id: &NetworkId) -> String {
        format!("n/{id}")
    }
    pub fn member(net: &NetworkId, node: &NodeId) -> String {
        format!("m/{net}/{node}")
    }
    pub fn device(net: &NetworkId, name: &str) -> String {
        format!("d/{net}/{name}")
    }
    pub fn invite(net: &NetworkId, id: &str) -> String {
        format!("i/{net}/{id}")
    }
    pub fn forward(id: &str) -> String {
        format!("f/{id}")
    }
    pub fn lighthouse(key: &NodeId) -> String {
        format!("l/{key}")
    }
}

/// True when a tombstone at `key` outranks a record of `version`.
fn blocked(tombs: &BTreeMap<String, Version>, key: &str, version: Version) -> bool {
    tombs.get(key).is_some_and(|t| *t >= version)
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

    fn labels_taken(&self) -> HashSet<String> {
        self.members
            .values()
            .map(|m| m.dns_name.clone())
            .chain(self.devices.values().map(|d| d.dns_name.clone()))
            .collect()
    }

    /// Unique DNS label for a hostname within this network.
    fn unique_label(&self, hostname: &str) -> String {
        unique_with(&dns_label(hostname), &self.labels_taken())
    }

    pub fn capacity(&self) -> u32 {
        let (lo, hi) = self.host_range();
        hi - lo + 1
    }

    fn addresses_taken(&self) -> HashSet<u32> {
        self.members
            .values()
            .map(|m| u32::from(m.address))
            .chain(self.devices.values().map(|d| u32::from(d.address)))
            .collect()
    }

    /// First free address scanning from `start` (an offset into the pool) and
    /// wrapping around.
    fn allocate_from(&self, start: u32) -> Option<Ipv4Addr> {
        let (lo, _) = self.host_range();
        let cap = self.capacity();
        let used = self.addresses_taken();
        (0..cap)
            .map(|i| lo + (start + i) % cap)
            .find(|a| !used.contains(a))
            .map(Ipv4Addr::from)
    }

    pub fn find_invite(&self, token: &[u8; 16]) -> Option<String> {
        let hash = ig_proto::Invite::token_hash(token);
        let now = now_secs();
        self.invites
            .values()
            .find(|i| i.token_hash == hash && i.usable(now))
            .map(|i| i.id.clone())
    }
}

fn unique_with(base: &str, taken: &HashSet<String>) -> String {
    if !taken.contains(base) {
        return base.to_string();
    }
    for i in 2.. {
        let candidate = format!("{base}-{i}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!()
}

impl Store {
    pub fn new(me: NodeId) -> Store {
        Store {
            networks: BTreeMap::new(),
            nodes: BTreeMap::new(),
            forwards: BTreeMap::new(),
            lighthouses: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            clock: 0,
            me,
        }
    }

    pub fn load(path: &Path, me: NodeId) -> Result<Store, StoreError> {
        let mut store: Store = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Store::new(me),
            Err(e) => return Err(e.into()),
        };
        store.me = me;
        Ok(store)
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

    pub fn me(&self) -> NodeId {
        self.me
    }

    /// Issue a version for a change made now.
    fn tick(&mut self) -> Version {
        self.clock = now_millis().max(self.clock + 1);
        Version {
            ts: self.clock,
            by: self.me,
        }
    }

    fn bury(&mut self, key: String, version: Version) {
        let e = self.tombstones.entry(key).or_insert(version);
        if version > *e {
            *e = version;
        }
    }

    /// Where this lighthouse starts scanning for free addresses: its share of
    /// the pool, by rank among the known lighthouses.
    fn slice_start(&self, net: &Network) -> u32 {
        let keys: Vec<&NodeId> = self.lighthouses.keys().collect();
        let n = keys.len().max(1) as u32;
        let rank = keys.iter().position(|k| **k == self.me).unwrap_or(0) as u32;
        (net.capacity() / n) * rank
    }

    fn allocate(&self, net: &Network) -> Option<Ipv4Addr> {
        net.allocate_from(self.slice_start(net))
    }

    /// Find a network by id (hex) or by name.
    pub fn resolve(&self, name_or_id: &str) -> Result<NetworkId, StoreError> {
        if let Ok(id) = name_or_id.parse::<NetworkId>() {
            if self.networks.contains_key(&id) {
                return Ok(id);
            }
        }
        let matches: Vec<NetworkId> = self
            .networks
            .values()
            .filter(|n| n.name == name_or_id)
            .map(|n| n.id)
            .collect();
        match matches.len() {
            0 => Err(StoreError::NoSuchNetwork(name_or_id.to_string())),
            1 => Ok(matches[0]),
            n => Err(StoreError::AmbiguousName(name_or_id.to_string(), n)),
        }
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
        let version = self.tick();
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
            invites: BTreeMap::new(),
            created_at: now_secs(),
            version,
        };
        self.networks.insert(id, net);
        self.ensure_lighthouse_members();
        Ok(&self.networks[&id])
    }

    pub fn delete_network(&mut self, id: NetworkId) -> Option<Network> {
        let net = self.networks.remove(&id)?;
        let v = self.tick();
        self.bury(keys::network(&id), v);
        let fwds: Vec<String> = self
            .forwards
            .values()
            .filter(|f| f.network == id)
            .map(|f| f.id.clone())
            .collect();
        for f in fwds {
            self.remove_forward(&f);
        }
        Some(net)
    }

    fn touch_network(
        &mut self,
        id: NetworkId,
        f: impl FnOnce(&mut Network),
    ) -> Result<(), StoreError> {
        let v = self.tick();
        let net = self
            .networks
            .get_mut(&id)
            .ok_or_else(|| StoreError::NoSuchNetwork(id.to_string()))?;
        f(net);
        net.version = v;
        Ok(())
    }

    pub fn set_policy(&mut self, id: NetworkId, policy: Policy) -> Result<(), StoreError> {
        self.touch_network(id, |n| n.policy = policy)
    }

    pub fn set_relay_limit(&mut self, id: NetworkId, limit: RelayLimit) -> Result<(), StoreError> {
        self.touch_network(id, |n| n.relay_limit = limit)
    }

    pub fn set_exposes_allowed(&mut self, id: NetworkId, allowed: bool) -> Result<(), StoreError> {
        self.touch_network(id, |n| n.exposes_allowed = allowed)
    }

    /// Add a member without an invite (lighthouses). Idempotent.
    pub fn add_member_direct(
        &mut self,
        network: NetworkId,
        node: NodeId,
        hostname: &str,
    ) -> Result<Ipv4Addr, StoreError> {
        {
            let rec = self.nodes.entry(node).or_default();
            if rec.hostname.is_empty() {
                rec.hostname = hostname.to_string();
                rec.os = "lighthouse".into();
            }
        }
        if let Some(m) = self
            .networks
            .get(&network)
            .and_then(|n| n.members.get(&node))
        {
            return Ok(m.address);
        }
        self.insert_member(network, node, hostname)
    }

    fn insert_member(
        &mut self,
        network: NetworkId,
        node: NodeId,
        hostname: &str,
    ) -> Result<Ipv4Addr, StoreError> {
        let version = self.tick();
        let net = self
            .networks
            .get(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        let address = self.allocate(net).ok_or(StoreError::Full)?;
        let address6 = net.address6_for(address);
        let dns_name = net.unique_label(hostname);
        self.networks
            .get_mut(&network)
            .expect("checked")
            .members
            .insert(
                node,
                Member {
                    address,
                    address6,
                    dns_name,
                    joined_at: now_secs(),
                    version,
                },
            );
        Ok(address)
    }

    /// Register another lighthouse and make it a member of every network.
    pub fn add_lighthouse(&mut self, mut rec: LighthouseRecord) -> Result<(), StoreError> {
        if self.lighthouses.contains_key(&rec.key) {
            return Err(StoreError::DuplicateLighthouse);
        }
        rec.version = self.tick();
        self.lighthouses.insert(rec.key, rec.clone());
        self.touch_node(rec.key, &rec.name, "lighthouse");
        self.ensure_lighthouse_members();
        Ok(())
    }

    /// Make sure this lighthouse is registered with the given name and address
    /// and is a member everywhere. A lighthouse that was removed by an admin
    /// stays removed: the tombstone wins until it is added again.
    pub fn ensure_lighthouse(&mut self, rec: LighthouseRecord) -> bool {
        let state = self
            .lighthouses
            .get(&rec.key)
            .map(|e| e.host != rec.host || e.port != rec.port || e.name != rec.name);
        let mut changed = false;
        match state {
            Some(false) => {}
            Some(true) => {
                let version = self.tick();
                let e = self.lighthouses.get_mut(&rec.key).expect("present");
                e.host = rec.host;
                e.port = rec.port;
                e.name = rec.name;
                e.version = version;
                changed = true;
            }
            None => {
                if self.tombstones.contains_key(&keys::lighthouse(&rec.key)) {
                    return false;
                }
                let version = self.tick();
                self.lighthouses.insert(
                    rec.key,
                    LighthouseRecord {
                        version,
                        ..rec.clone()
                    },
                );
                self.touch_node(rec.key, &rec.name, "lighthouse");
                changed = true;
            }
        }
        changed | self.ensure_lighthouse_members()
    }

    /// Every known lighthouse is a member of every network. Returns true if a
    /// membership was added.
    pub fn ensure_lighthouse_members(&mut self) -> bool {
        let lhs: Vec<(NodeId, String)> = self
            .lighthouses
            .values()
            .map(|l| (l.key, l.name.clone()))
            .collect();
        let ids: Vec<NetworkId> = self.networks.keys().copied().collect();
        let mut changed = false;
        for id in ids {
            for (key, name) in &lhs {
                if !self.networks[&id].members.contains_key(key)
                    && self.insert_member(id, *key, name).is_ok()
                {
                    changed = true;
                }
            }
        }
        changed
    }

    pub fn remove_lighthouse(&mut self, key: &NodeId) -> Result<(), StoreError> {
        self.lighthouses
            .remove(key)
            .ok_or_else(|| StoreError::NoSuchLighthouse(key.short()))?;
        let v = self.tick();
        self.bury(keys::lighthouse(key), v);
        let ids: Vec<NetworkId> = self.networks.keys().copied().collect();
        for id in ids {
            let _ = self.remove_member(id, key);
        }
        let fwds: Vec<String> = self
            .forwards
            .values()
            .filter(|f| f.lighthouse == *key)
            .map(|f| f.id.clone())
            .collect();
        for f in fwds {
            self.remove_forward(&f);
        }
        Ok(())
    }

    /// Lighthouses by name.
    pub fn lighthouses_ordered(&self) -> Vec<LighthouseRecord> {
        let mut v: Vec<LighthouseRecord> = self.lighthouses.values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name).then(a.key.cmp(&b.key)));
        v
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
            .get(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        if let Some(m) = net.members.get(&node) {
            return Ok(m.address);
        }
        let invite_id = net.find_invite(token).ok_or(StoreError::BadInvite)?;
        let address = self.insert_member(network, node, &hostname)?;
        let me = self.me;
        let inv = self
            .networks
            .get_mut(&network)
            .expect("checked")
            .invites
            .get_mut(&invite_id)
            .expect("found");
        *inv.used.entry(me).or_insert(0) += 1;
        Ok(address)
    }

    pub fn create_invite(
        &mut self,
        network: NetworkId,
        id: &str,
        label: String,
        token_hash: [u8; 32],
        uses: u32,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        let version = self.tick();
        let net = self
            .networks
            .get_mut(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        net.invites.insert(
            id.to_string(),
            InviteRecord {
                id: id.to_string(),
                label,
                token_hash,
                uses,
                used: BTreeMap::new(),
                expires_at,
                version,
            },
        );
        Ok(())
    }

    pub fn revoke_invite(&mut self, network: NetworkId, id: &str) -> Result<(), StoreError> {
        let net = self
            .networks
            .get_mut(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        net.invites
            .remove(id)
            .ok_or_else(|| StoreError::NoSuchInvite(id.to_string()))?;
        let v = self.tick();
        self.bury(keys::invite(&network, id), v);
        Ok(())
    }

    pub fn add_forward(&mut self, mut rec: ForwardRecord) {
        rec.version = self.tick();
        self.forwards.insert(rec.id.clone(), rec);
    }

    pub fn remove_forward(&mut self, id: &str) -> Option<ForwardRecord> {
        let rec = self.forwards.remove(id)?;
        let v = self.tick();
        self.bury(keys::forward(id), v);
        Some(rec)
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
        let ids: Vec<NetworkId> = self.networks.keys().copied().collect();
        for id in ids {
            let net = &self.networks[&id];
            let Some(current) = net.members.get(node).map(|m| m.dns_name.clone()) else {
                continue;
            };
            if current == base || current.starts_with(&format!("{base}-")) {
                continue;
            }
            let label = net.unique_label(&hostname);
            let v = self.tick();
            let m = self
                .networks
                .get_mut(&id)
                .expect("present")
                .members
                .get_mut(node)
                .expect("present");
            m.dns_name = label;
            m.version = v;
            changed.push(id);
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
        let version = self.tick();
        let net = self
            .networks
            .get(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        if net.devices.contains_key(name) {
            return Err(StoreError::DuplicateDevice(name.to_string()));
        }
        if let Some(d) = net
            .devices
            .values()
            .find(|d| d.target == target || (target6.is_some() && d.target6 == target6))
        {
            return Err(StoreError::DuplicateTarget(d.name.clone()));
        }
        let address = self.allocate(net).ok_or(StoreError::Full)?;
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
            version,
        };
        self.networks
            .get_mut(&network)
            .expect("checked")
            .devices
            .insert(name.to_string(), dev.clone());
        Ok(dev)
    }

    pub fn remove_device(&mut self, network: NetworkId, name: &str) -> Result<(), StoreError> {
        let net = self
            .networks
            .get_mut(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        net.devices
            .remove(name)
            .ok_or_else(|| StoreError::NoSuchDevice(name.to_string()))?;
        let v = self.tick();
        self.bury(keys::device(&network, name), v);
        Ok(())
    }

    pub fn remove_member(&mut self, network: NetworkId, node: &NodeId) -> Result<(), StoreError> {
        let net = self
            .networks
            .get_mut(&network)
            .ok_or_else(|| StoreError::NoSuchNetwork(network.to_string()))?;
        net.members.remove(node).ok_or(StoreError::NotMember)?;
        let v = self.tick();
        self.bury(keys::member(&network, node), v);
        Ok(())
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

    /// Drop expired and used-up invites. Returns true if anything changed.
    pub fn prune_invites(&mut self) -> bool {
        let now = now_secs();
        let mut gone: Vec<(NetworkId, String)> = Vec::new();
        for n in self.networks.values() {
            for i in n.invites.values() {
                if !i.usable(now) {
                    gone.push((n.id, i.id.clone()));
                }
            }
        }
        let changed = !gone.is_empty();
        for (net, id) in gone {
            let _ = self.revoke_invite(net, &id);
        }
        changed
    }

    // ---- merging ----------------------------------------------------------------

    /// Fold another lighthouse's copy into this one. Both sides calling this with
    /// each other's copy end with identical stores.
    pub fn merge(&mut self, other: &Store) -> MergeOutcome {
        let mut before = self.clone();
        self.clock = self.clock.max(other.clock);
        before.clock = self.clock;

        for (k, v) in &other.tombstones {
            self.bury(k.clone(), *v);
        }
        let tombs = self.tombstones.clone();

        for (k, rec) in &other.lighthouses {
            if blocked(&tombs, &keys::lighthouse(k), rec.version) {
                continue;
            }
            match self.lighthouses.get(k) {
                Some(mine) if mine.version >= rec.version => {}
                _ => {
                    self.lighthouses.insert(*k, rec.clone());
                }
            }
        }
        for (k, rec) in &other.forwards {
            if blocked(&tombs, &keys::forward(k), rec.version) {
                continue;
            }
            match self.forwards.get(k) {
                Some(mine) if mine.version >= rec.version => {}
                _ => {
                    self.forwards.insert(k.clone(), rec.clone());
                }
            }
        }
        for (k, rec) in &other.nodes {
            match self.nodes.get(k) {
                Some(mine) if mine.last_seen >= rec.last_seen => {}
                _ => {
                    self.nodes.insert(*k, rec.clone());
                }
            }
        }
        for (id, net) in &other.networks {
            if blocked(&tombs, &keys::network(id), net.version) {
                continue;
            }
            let mine = self.networks.entry(*id).or_insert_with(|| Network {
                members: BTreeMap::new(),
                invites: BTreeMap::new(),
                devices: BTreeMap::new(),
                ..net.clone()
            });
            if mine.version < net.version {
                mine.name = net.name.clone();
                mine.cidr = net.cidr;
                mine.cidr6 = net.cidr6;
                mine.policy = net.policy.clone();
                mine.relay_limit = net.relay_limit;
                mine.exposes_allowed = net.exposes_allowed;
                mine.created_at = net.created_at;
                mine.version = net.version;
            }
            for (node, m) in &net.members {
                if blocked(&tombs, &keys::member(id, node), m.version) {
                    continue;
                }
                match mine.members.get(node) {
                    Some(cur) if cur.version >= m.version => {}
                    _ => {
                        mine.members.insert(*node, m.clone());
                    }
                }
            }
            for (name, d) in &net.devices {
                if blocked(&tombs, &keys::device(id, name), d.version) {
                    continue;
                }
                match mine.devices.get(name) {
                    Some(cur) if cur.version >= d.version => {}
                    _ => {
                        mine.devices.insert(name.clone(), d.clone());
                    }
                }
            }
            for (iid, inv) in &net.invites {
                if blocked(&tombs, &keys::invite(id, iid), inv.version) {
                    continue;
                }
                let cur = mine
                    .invites
                    .entry(iid.clone())
                    .or_insert_with(|| inv.clone());
                if cur.version < inv.version {
                    let used = std::mem::take(&mut cur.used);
                    *cur = inv.clone();
                    for (lh, n) in used {
                        let e = cur.used.entry(lh).or_insert(0);
                        *e = (*e).max(n);
                    }
                } else {
                    for (lh, n) in &inv.used {
                        let e = cur.used.entry(*lh).or_insert(0);
                        *e = (*e).max(*n);
                    }
                }
            }
        }

        self.apply_tombstones();
        let ids: Vec<NetworkId> = self.networks.keys().copied().collect();
        for id in ids {
            self.resolve_conflicts(id);
        }
        self.ensure_lighthouse_members();

        let all: BTreeSet<NetworkId> = before
            .networks
            .keys()
            .chain(self.networks.keys())
            .copied()
            .collect();
        let networks = all
            .into_iter()
            .filter(|id| before.networks.get(id) != self.networks.get(id))
            .collect();
        MergeOutcome {
            changed: *self != before,
            networks,
        }
    }

    /// Remove every record that a tombstone outranks.
    fn apply_tombstones(&mut self) {
        let tombs = self.tombstones.clone();
        for (key, tv) in &tombs {
            let mut parts = key.splitn(3, '/');
            let (Some(kind), Some(a)) = (parts.next(), parts.next()) else {
                continue;
            };
            let b = parts.next();
            match (kind, b) {
                ("n", None) => {
                    if let Ok(id) = a.parse::<NetworkId>() {
                        if self.networks.get(&id).is_some_and(|n| n.version <= *tv) {
                            self.networks.remove(&id);
                        }
                    }
                }
                ("l", None) => {
                    if let Ok(k) = a.parse::<NodeId>() {
                        if self.lighthouses.get(&k).is_some_and(|l| l.version <= *tv) {
                            self.lighthouses.remove(&k);
                        }
                    }
                }
                ("f", None) => {
                    if self.forwards.get(a).is_some_and(|f| f.version <= *tv) {
                        self.forwards.remove(a);
                    }
                }
                ("m", Some(node)) => {
                    if let (Ok(id), Ok(n)) = (a.parse::<NetworkId>(), node.parse::<NodeId>()) {
                        if let Some(net) = self.networks.get_mut(&id) {
                            if net.members.get(&n).is_some_and(|m| m.version <= *tv) {
                                net.members.remove(&n);
                            }
                        }
                    }
                }
                ("d", Some(name)) => {
                    if let Ok(id) = a.parse::<NetworkId>() {
                        if let Some(net) = self.networks.get_mut(&id) {
                            if net.devices.get(name).is_some_and(|d| d.version <= *tv) {
                                net.devices.remove(name);
                            }
                        }
                    }
                }
                ("i", Some(iid)) => {
                    if let Ok(id) = a.parse::<NetworkId>() {
                        if let Some(net) = self.networks.get_mut(&id) {
                            if net.invites.get(iid).is_some_and(|i| i.version <= *tv) {
                                net.invites.remove(iid);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// After a merge, two records may hold the same address, the same DNS label
    /// or (devices) the same physical target. Walk the records in version order:
    /// the older one keeps what it has, the newer one is moved or dropped. Every
    /// lighthouse runs the same walk on the same data, so they agree.
    fn resolve_conflicts(&mut self, id: NetworkId) {
        #[derive(Clone)]
        enum Who {
            Member(NodeId),
            Device(String),
        }
        let Some(net) = self.networks.get(&id) else {
            return;
        };
        let mut order: Vec<(Version, String, Who)> = net
            .members
            .iter()
            .map(|(n, m)| (m.version, format!("m{n}"), Who::Member(*n)))
            .chain(
                net.devices
                    .iter()
                    .map(|(name, d)| (d.version, format!("d{name}"), Who::Device(name.clone()))),
            )
            .collect();
        order.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let (lo, hi) = net.host_range();
        let mut addrs: HashSet<u32> = HashSet::new();
        let mut labels: HashSet<String> = HashSet::new();
        let mut targets: HashSet<Ipv4Addr> = HashSet::new();
        let mut drop: Vec<(Who, Version)> = Vec::new();

        let net = self.networks.get_mut(&id).expect("present");
        for (version, _, who) in order {
            let (address, label, target) = match &who {
                Who::Member(n) => {
                    let m = &net.members[n];
                    (m.address, m.dns_name.clone(), None)
                }
                Who::Device(name) => {
                    let d = &net.devices[name];
                    (d.address, d.dns_name.clone(), Some(d.target))
                }
            };
            if let Some(t) = target {
                if !targets.insert(t) {
                    tracing::warn!(network = %net.name, target = %t, "dropping a device that duplicates another's physical address after a merge");
                    drop.push((who.clone(), version));
                    continue;
                }
            }
            let mut new_address = None;
            if !addrs.insert(u32::from(address)) {
                match (lo..=hi).find(|a| !addrs.contains(a)) {
                    Some(a) => {
                        addrs.insert(a);
                        new_address = Some(Ipv4Addr::from(a));
                        tracing::warn!(network = %net.name, from = %address, to = %Ipv4Addr::from(a), "address allocated twice; moving the newer record");
                    }
                    None => {
                        drop.push((who.clone(), version));
                        continue;
                    }
                }
            }
            let mut new_label = None;
            if !labels.insert(label.clone()) {
                let l = unique_with(&label, &labels);
                labels.insert(l.clone());
                new_label = Some(l);
            }
            if new_address.is_none() && new_label.is_none() {
                continue;
            }
            match &who {
                Who::Member(n) => {
                    let m = net.members.get_mut(n).expect("present");
                    if let Some(a) = new_address {
                        m.address = a;
                        if m.address6.is_some() {
                            m.address6 = net.cidr6.map(|c6| {
                                let off = u32::from(a) - u32::from(net.cidr.network());
                                Ipv6Addr::from(u128::from(c6.network()) + off as u128)
                            });
                        }
                    }
                    if let Some(l) = new_label {
                        m.dns_name = l;
                    }
                }
                Who::Device(name) => {
                    let d = net.devices.get_mut(name).expect("present");
                    if let Some(a) = new_address {
                        d.address = a;
                        if d.address6.is_some() {
                            d.address6 = net.cidr6.map(|c6| {
                                let off = u32::from(a) - u32::from(net.cidr.network());
                                Ipv6Addr::from(u128::from(c6.network()) + off as u128)
                            });
                        }
                    }
                    if let Some(l) = new_label {
                        d.dns_name = l;
                    }
                }
            }
        }
        for (who, version) in drop {
            let net = self.networks.get_mut(&id).expect("present");
            match who {
                Who::Member(n) => {
                    net.members.remove(&n);
                    self.bury(keys::member(&id, &n), version.after());
                }
                Who::Device(name) => {
                    net.devices.remove(&name);
                    self.bury(keys::device(&id, &name), version.after());
                }
            }
        }
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

    fn invite(s: &mut Store, net: NetworkId, uses: u32) -> [u8; 16] {
        let token: [u8; 16] = ig_proto::random_array();
        let id: String = ig_proto::random_array::<4>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        s.create_invite(
            net,
            &id,
            String::new(),
            ig_proto::Invite::token_hash(&token),
            uses,
            now_secs() + 3600,
        )
        .unwrap();
        token
    }

    fn lh(s: &mut Store, name: &str) {
        let key = s.me();
        s.ensure_lighthouse(LighthouseRecord {
            key,
            name: name.into(),
            host: name.into(),
            port: 7777,
            version: Version::default(),
        });
    }

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn join_allocates_sequential_addresses_and_consumes_invites() {
        let mut s = Store::default();
        let net = s
            .create_network(
                "dev",
                "10.90.0.0/29".parse().unwrap(),
                Some("fd42::/64".parse().unwrap()),
            )
            .unwrap()
            .id;
        let token = invite(&mut s, net, 2);
        let a = NodeId(ig_proto::random_array());
        let b = NodeId(ig_proto::random_array());
        let c = NodeId(ig_proto::random_array());
        s.touch_node(a, "Laptop", "linux");
        s.touch_node(b, "laptop", "windows");
        assert_eq!(
            s.join(net, a, &token).unwrap(),
            "10.90.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            s.join(net, b, &token).unwrap(),
            "10.90.0.3".parse::<Ipv4Addr>().unwrap()
        );
        let ma = &s.networks[&net].members[&a];
        assert_eq!(ma.address6, Some("fd42::2".parse().unwrap()));
        assert_eq!(ma.dns_name, "laptop");
        assert_eq!(s.networks[&net].members[&b].dns_name, "laptop-2");
        // Used up.
        assert!(matches!(s.join(net, c, &token), Err(StoreError::BadInvite)));
        // Re-join is idempotent and needs no invite.
        assert_eq!(
            s.join(net, a, &[0u8; 16]).unwrap(),
            "10.90.0.2".parse::<Ipv4Addr>().unwrap()
        );
        s.remove_member(net, &a).unwrap();
        let token2 = invite(&mut s, net, 10);
        // Freed address is reused.
        assert_eq!(
            s.join(net, c, &token2).unwrap(),
            "10.90.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert!(s.share_network(&b, &c));
        assert!(!s.share_network(&a, &b));
        // Devices take addresses from the same pool and unique labels.
        let d = s
            .add_device(
                net,
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
            s.add_device(net, "laptop", "192.168.1.9".parse().unwrap(), None, vec![]),
            Err(StoreError::DuplicateDevice(_))
        ));
        s.remove_device(net, "laptop").unwrap();
        assert!(s.tombstones.contains_key(&keys::device(&net, "laptop")));
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
        let mut s = Store::new(id(1));
        let net = s
            .create_network("dev", "10.90.0.0/24".parse().unwrap(), None)
            .unwrap()
            .id;
        invite(&mut s, net, 1);
        s.save(&path).unwrap();
        let back = Store::load(&path, id(1)).unwrap();
        assert_eq!(back.networks[&net].invites.len(), 1);
        assert_eq!(back, s);
        assert_eq!(back.me(), id(1));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Two lighthouses that each registered the other, then worked apart.
    fn pair() -> (Store, Store, NetworkId) {
        let mut a = Store::new(id(1));
        let mut b = Store::new(id(2));
        lh(&mut a, "a");
        lh(&mut b, "b");
        a.add_lighthouse(b.lighthouses[&id(2)].clone()).unwrap();
        b.add_lighthouse(a.lighthouses[&id(1)].clone()).unwrap();
        let net = a
            .create_network(
                "dev",
                "10.90.0.0/24".parse().unwrap(),
                Some("fd42::/64".parse().unwrap()),
            )
            .unwrap()
            .id;
        assert!(b.merge(&a).changed);
        a.merge(&b);
        assert_eq!(a, b, "both copies agree after the first exchange");
        (a, b, net)
    }

    #[test]
    fn lighthouses_allocate_from_their_own_slices() {
        let (mut a, mut b, net) = pair();
        let ta = invite(&mut a, net, 5);
        let tb = invite(&mut b, net, 5);
        let n1 = id(11);
        let n2 = id(12);
        a.touch_node(n1, "one", "linux");
        b.touch_node(n2, "two", "linux");
        let addr1 = a.join(net, n1, &ta).unwrap();
        let addr2 = b.join(net, n2, &tb).unwrap();
        assert_ne!(addr1, addr2);
        // Ranks: id(1) < id(2), so `a` scans from the bottom, `b` from the middle.
        assert!(u32::from(addr2) - u32::from("10.90.0.2".parse::<Ipv4Addr>().unwrap()) >= 100);
        assert!(a.merge(&b).changed);
        assert!(b.merge(&a).changed);
        assert_eq!(a, b);
        assert_eq!(
            a.networks[&net].members.len(),
            4,
            "two lighthouses, two nodes"
        );
        assert_eq!(a.networks[&net].members[&n2].address, addr2);
    }

    #[test]
    fn merge_resolves_duplicate_addresses_and_labels_deterministically() {
        let (mut a, mut b, net) = pair();
        // Force a collision: make both sides think they are rank 0.
        let mut a_alone = a.clone();
        a_alone.lighthouses.remove(&id(2));
        let mut b_alone = b.clone();
        b_alone.lighthouses.remove(&id(1));
        let ta = invite(&mut a_alone, net, 5);
        let tb = invite(&mut b_alone, net, 5);
        let n1 = id(11);
        let n2 = id(12);
        a_alone.touch_node(n1, "laptop", "linux");
        b_alone.touch_node(n2, "laptop", "linux");
        let addr1 = a_alone.join(net, n1, &ta).unwrap();
        let addr2 = b_alone.join(net, n2, &tb).unwrap();
        assert_eq!(addr1, addr2, "same slice, same first free address");
        a.merge(&a_alone);
        b.merge(&b_alone);
        a.merge(&b);
        b.merge(&a);
        assert_eq!(a, b);
        let m = &a.networks[&net].members;
        assert_ne!(m[&n1].address, m[&n2].address);
        assert_ne!(m[&n1].dns_name, m[&n2].dns_name);
        assert!(m.values().all(|x| x.address6.is_some()));
        for x in m.values() {
            let off = u32::from(x.address) - u32::from("10.90.0.0".parse::<Ipv4Addr>().unwrap());
            assert_eq!(
                x.address6.unwrap(),
                Ipv6Addr::from(u128::from("fd42::".parse::<Ipv6Addr>().unwrap()) + off as u128)
            );
        }
        // The older record kept its address; the newer one moved.
        let older = if m[&n1].version < m[&n2].version {
            n1
        } else {
            n2
        };
        assert_eq!(m[&older].address, addr1);
    }

    #[test]
    fn tombstones_win_over_older_copies_and_invites_add_up() {
        let (mut a, mut b, net) = pair();
        let t = invite(&mut a, net, 3);
        b.merge(&a);
        let iid = a.networks[&net].invites.keys().next().unwrap().clone();
        // Each side consumes the same invite once while apart.
        a.touch_node(id(11), "x", "linux");
        b.touch_node(id(12), "y", "linux");
        a.join(net, id(11), &t).unwrap();
        b.join(net, id(12), &t).unwrap();
        a.merge(&b);
        b.merge(&a);
        assert_eq!(a.networks[&net].invites[&iid].uses_left(), 1);
        assert_eq!(a, b);
        // A removes a device while B still has the old copy.
        let d = a
            .add_device(net, "nas", "192.168.1.5".parse().unwrap(), None, vec![])
            .unwrap();
        b.merge(&a);
        assert!(b.networks[&net].devices.contains_key("nas"));
        a.remove_device(net, "nas").unwrap();
        a.merge(&b);
        assert!(
            !a.networks[&net].devices.contains_key("nas"),
            "an older copy cannot resurrect a removed record"
        );
        b.merge(&a);
        assert!(!b.networks[&net].devices.contains_key("nas"));
        assert_eq!(a, b);
        // Re-adding after removal works and propagates.
        let d2 = b.add_device(net, "nas", d.target, None, vec![]).unwrap();
        a.merge(&b);
        assert_eq!(a.networks[&net].devices["nas"], d2);
        // Deleting a network on one side deletes it on the other.
        b.delete_network(net);
        a.merge(&b);
        assert!(a.networks.is_empty());
        assert_eq!(a, b);
    }

    #[test]
    fn concurrent_devices_with_one_target_keep_exactly_one() {
        let (mut a, mut b, net) = pair();
        a.add_device(net, "printer", "192.168.1.9".parse().unwrap(), None, vec![])
            .unwrap();
        b.add_device(net, "printer", "192.168.1.9".parse().unwrap(), None, vec![])
            .unwrap();
        a.merge(&b);
        b.merge(&a);
        assert_eq!(a, b);
        assert_eq!(a.networks[&net].devices.len(), 1);
        // A second network created on each side with the same name is kept, and
        // the name becomes ambiguous.
        a.create_network("ops", "10.91.0.0/24".parse().unwrap(), None)
            .unwrap();
        b.create_network("ops", "10.92.0.0/24".parse().unwrap(), None)
            .unwrap();
        a.merge(&b);
        b.merge(&a);
        assert_eq!(a, b);
        assert_eq!(a.networks.len(), 3);
        assert!(matches!(
            a.resolve("ops"),
            Err(StoreError::AmbiguousName(_, 2))
        ));
        // Every lighthouse is a member of every network after the merge.
        for n in a.networks.values() {
            assert!(n.members.contains_key(&id(1)) && n.members.contains_key(&id(2)));
        }
    }

    #[test]
    fn removed_lighthouse_stays_removed_until_added_again() {
        let (mut a, mut b, net) = pair();
        a.remove_lighthouse(&id(2)).unwrap();
        b.merge(&a);
        assert!(!b.lighthouses.contains_key(&id(2)));
        assert!(!b.networks[&net].members.contains_key(&id(2)));
        // b restarts and tries to register itself: the tombstone holds.
        lh(&mut b, "b");
        assert!(!b.lighthouses.contains_key(&id(2)));
        // An admin adds it back; the new record outranks the tombstone.
        a.add_lighthouse(LighthouseRecord {
            key: id(2),
            name: "b".into(),
            host: "b".into(),
            port: 7777,
            version: Version::default(),
        })
        .unwrap();
        b.merge(&a);
        assert!(b.lighthouses.contains_key(&id(2)));
        assert!(b.networks[&net].members.contains_key(&id(2)));
        assert_eq!(a, b);
    }
}
