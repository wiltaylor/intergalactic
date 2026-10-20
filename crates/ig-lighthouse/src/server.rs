//! Lighthouse runtime: control sessions, UDP disco/relay, broadcasts and admin.

use crate::store::{now_secs, InviteRecord, Store, StoreError};
use ig_core::{Engine, EngineConfig, EngineEvent, NoProtector, TunDevice, TunScope};
use ig_node::forward_os::ForwardRule;
use ig_proto::admin::{
    AdminRequest, AdminResponse, DeviceSummary, ForwardSummary, InviteSummary, LighthouseInfo,
    NetworkSummary, NodeSummary,
};
use ig_proto::control::LighthouseRef;
use ig_proto::control::{
    ClientHello, DeviceInfo, FromLighthouse, NetworkInfo, PeerInfo, ServerHello, ToLighthouse,
};
use ig_proto::noise::NoiseStream;
use ig_proto::replication::{FromPrimary, ToPrimary};
use ig_proto::tunnel::{ForwardInfo, ForwardKind, ForwardProto};
use ig_proto::udp::{bind_dual_stack, canonical, reachable, to_wire};
use ig_proto::{disco, Invite, Keypair, NetworkId, NodeId, RelayLimit, PROTOCOL_VERSION};
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How long an observed UDP address stays valid without a new probe.
const UDP_ADDR_TTL: Duration = Duration::from_secs(90);
/// Coalescing window for state broadcasts.
const BROADCAST_DEBOUNCE: Duration = Duration::from_millis(150);
const MAX_RELAY_PAYLOAD: usize = 2048;
/// A control session that stays silent this long is considered dead. Nodes ping
/// every 15 s, so this catches a laptop that vanished without closing TCP and
/// lets gateway failover happen within a minute.
const SESSION_IDLE: Duration = Duration::from_secs(45);

#[derive(Clone, Debug)]
pub struct LighthouseConfig {
    pub keypair: Keypair,
    /// Address for both TCP control and UDP disco/relay.
    pub listen: SocketAddr,
    /// Host name or IP written into invites.
    pub public_host: String,
    /// Port written into invites (normally `listen.port()`, differs behind port forwards).
    pub public_port: u16,
    /// Where to persist state. `None` keeps everything in memory (tests).
    pub state_path: Option<PathBuf>,
    /// DNS suffix for peer names, e.g. `ig.internal`.
    pub dns_domain: String,
    /// Relay limit applied to networks that have no limit of their own.
    pub default_relay_limit: RelayLimit,
    /// Public ports handed out for ephemeral forwards, inclusive.
    pub forward_range: (u16, u16),
    /// This lighthouse's name; also its hostname and DNS label as a member.
    pub name: String,
    pub role: Role,
    /// How this lighthouse joins the overlay as a member.
    pub overlay: Overlay,
}

#[derive(Clone, Debug)]
pub enum Role {
    Primary,
    /// Replicate the store from this primary and proxy writes to it.
    Replica(LighthouseRef),
}

/// Builds a TUN device for one network (tests and embedders).
pub type TunFactory =
    Arc<dyn Fn(&NetworkInfo) -> std::io::Result<Arc<dyn TunDevice>> + Send + Sync>;
type TunEntry = (NetworkInfo, Arc<dyn TunDevice>);

/// TUN strategy for the embedded node engine.
#[derive(Clone)]
pub enum Overlay {
    /// No overlay membership (admin-only lighthouse; forwards unavailable).
    Off,
    /// Real TUN devices and nftables rules. Needs CAP_NET_ADMIN.
    Kernel,
    /// Caller-provided TUN devices, no kernel rules (tests).
    Custom(TunFactory),
}

impl std::fmt::Debug for Overlay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Overlay::Off => f.write_str("Off"),
            Overlay::Kernel => f.write_str("Kernel"),
            Overlay::Custom(_) => f.write_str("Custom"),
        }
    }
}

/// Primary side: one connected replica.
#[derive(Clone)]
pub struct ReplicaLink {
    tx: mpsc::Sender<FromPrimary>,
    abort: Arc<tokio::sync::Notify>,
}

/// Ephemeral forward held in memory for the life of the node's session.
#[derive(Clone, Debug)]
struct Ephemeral {
    id: String,
    network: NetworkId,
    node: NodeId,
    proto: ForwardProto,
    public_port: u16,
    target: String,
    label: String,
}

const MAX_EPHEMERAL_PER_NODE: usize = 8;

struct Session {
    node: NodeId,
    hostname: String,
    os: String,
    token: [u8; 32],
    tx: mpsc::Sender<FromLighthouse>,
    local_endpoints: RwLock<Vec<SocketAddr>>,
    /// LAN prefixes the node reported; empty unless it offered to be a gateway.
    subnets: RwLock<Vec<Ipv4Net>>,
    subnets6: RwLock<Vec<ipnet::Ipv6Net>>,
    gateway: bool,
    last_seen: Mutex<Instant>,
    abort: tokio::sync::Notify,
}

pub struct Inner {
    pub config: LighthouseConfig,
    store: Mutex<Store>,
    sessions: RwLock<HashMap<NodeId, Arc<Session>>>,
    /// node -> (observed UDP address, when)
    udp_addrs: RwLock<HashMap<NodeId, (SocketAddr, Instant)>>,
    /// reverse index for relay source lookup
    udp_nodes: RwLock<HashMap<SocketAddr, NodeId>>,
    udp: UdpSocket,
    dual_stack: bool,
    /// Active gateway per (network, device name). Kept so a device does not
    /// hop between equally good gateways on every state push.
    active_gateways: Mutex<HashMap<(NetworkId, String), NodeId>>,
    ephemeral: Mutex<Vec<Ephemeral>>,
    /// Primary side: replication links to registered replicas.
    replicas: RwLock<HashMap<NodeId, ReplicaLink>>,
    /// Replica side: link to the primary while it is up.
    primary_link: Mutex<Option<mpsc::Sender<ToPrimary>>>,
    /// Embedded node engine (overlay membership) and its TUNs.
    engine: Mutex<Option<Engine>>,
    tuns: Mutex<HashMap<NetworkId, TunEntry>>,
    /// Forward NAT rules this lighthouse currently publishes.
    rules: Mutex<Vec<ForwardRule>>,
    /// Relay token buckets: per (network, node) and per network.
    buckets: Mutex<Buckets>,
    dirty: Mutex<HashSet<NetworkId>>,
    dirty_notify: tokio::sync::Notify,
    started: Instant,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct Lighthouse {
    inner: Arc<Inner>,
    tcp_addr: SocketAddr,
}

impl Lighthouse {
    pub async fn start(config: LighthouseConfig) -> anyhow::Result<Lighthouse> {
        let mut store = match &config.state_path {
            Some(p) => Store::load(p)?,
            None => Store::default(),
        };
        let tcp = TcpListener::bind(config.listen).await?;
        let tcp_addr = tcp.local_addr()?;
        let mut config = config;
        if config.public_port == 0 {
            // Port 0 means "whatever we bound": make invites and the self record agree.
            config.public_port = tcp_addr.port();
        }
        if matches!(config.role, Role::Primary) {
            // The primary is a member of every network it serves.
            let changed = store.ensure_lighthouse(crate::store::LighthouseRecord {
                key: config.keypair.public,
                name: config.name.clone(),
                host: config.public_host.clone(),
                port: config.public_port,
                primary: true,
            });
            if changed {
                if let Some(p) = &config.state_path {
                    store.save(p)?;
                }
            }
        }
        let (udp, dual_stack) = bind_dual_stack(config.listen.ip(), tcp_addr.port())?;
        let inner = Arc::new(Inner {
            config,
            store: Mutex::new(store),
            sessions: RwLock::new(HashMap::new()),
            udp_addrs: RwLock::new(HashMap::new()),
            udp_nodes: RwLock::new(HashMap::new()),
            udp,
            dual_stack,
            active_gateways: Mutex::new(HashMap::new()),
            ephemeral: Mutex::new(Vec::new()),
            replicas: RwLock::new(HashMap::new()),
            primary_link: Mutex::new(None),
            engine: Mutex::new(None),
            tuns: Mutex::new(HashMap::new()),
            rules: Mutex::new(Vec::new()),
            buckets: Mutex::new(Buckets::default()),
            dirty: Mutex::new(HashSet::new()),
            dirty_notify: tokio::sync::Notify::new(),
            started: Instant::now(),
            tasks: Mutex::new(Vec::new()),
        });
        let t1 = tokio::spawn(accept_loop(inner.clone(), tcp));
        let t2 = tokio::spawn(udp_loop(inner.clone()));
        let t3 = tokio::spawn(broadcast_loop(inner.clone()));
        let t4 = tokio::spawn(housekeeping(inner.clone()));
        let t5 = tokio::spawn(reap_idle_sessions(inner.clone()));
        inner.tasks.lock().extend([t1, t2, t3, t4, t5]);
        if let Role::Replica(primary) = &inner.config.role {
            let t = tokio::spawn(crate::replication::run_replica(
                inner.clone(),
                primary.clone(),
            ));
            inner.tasks.lock().push(t);
        }
        if !matches!(inner.config.overlay, Overlay::Off) {
            inner.start_engine(tcp_addr.port()).await?;
        }
        inner.reconcile_forwards();
        tracing::info!(addr = %tcp_addr, dual_stack, key = %inner.config.keypair.public, name = %inner.config.name, role = ?inner.config.role, overlay = ?inner.config.overlay, dns_domain = %inner.config.dns_domain, "lighthouse listening");
        Ok(Lighthouse { inner, tcp_addr })
    }

    /// Status of the embedded node engine, if the overlay is on.
    pub fn engine_status(&self) -> Option<ig_proto::ipc::StatusReport> {
        self.inner.engine.lock().as_ref().map(|e| e.status())
    }

    /// Forward NAT rules this lighthouse currently publishes.
    pub fn forward_rules(&self) -> Vec<ForwardRule> {
        self.inner.rules.lock().clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.tcp_addr
    }

    pub fn public_key(&self) -> NodeId {
        self.inner.config.keypair.public
    }

    pub fn admin(&self, req: AdminRequest) -> AdminResponse {
        self.inner.admin(req)
    }

    pub async fn shutdown(&self) {
        let engine = self.inner.engine.lock().take();
        if let Some(e) = engine {
            e.shutdown().await;
        }
        if matches!(self.inner.config.overlay, Overlay::Kernel) {
            ig_node::forward_os::remove();
        }
        // Close replication links so replicas notice at once.
        let links: Vec<ReplicaLink> = self
            .inner
            .replicas
            .write()
            .drain()
            .map(|(_, l)| l)
            .collect();
        for l in links {
            l.abort.notify_one();
        }
        for t in self.inner.tasks.lock().drain(..) {
            t.abort();
        }
        let sessions: Vec<_> = self
            .inner
            .sessions
            .write()
            .drain()
            .map(|(_, s)| s)
            .collect();
        for s in sessions {
            s.abort.notify_one();
        }
    }
}

/// Token bucket in bytes. Refills at `rate` bytes/s up to one second of burst.
struct Bucket {
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl Bucket {
    fn new(kbps: u32) -> Self {
        let rate = kbps as f64 * 1000.0 / 8.0;
        Bucket {
            tokens: rate,
            rate,
            last: Instant::now(),
        }
    }

    fn take(&mut self, bytes: usize, now: Instant) -> bool {
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.rate);
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct Buckets {
    per_node: HashMap<(NetworkId, NodeId), (u32, Bucket)>,
    per_network: HashMap<NetworkId, (u32, Bucket)>,
}

impl Buckets {
    /// Returns true if `bytes` may be relayed under `limit`.
    fn allow(&mut self, network: NetworkId, node: NodeId, limit: RelayLimit, bytes: usize) -> bool {
        if limit.is_unlimited() {
            return true;
        }
        let now = Instant::now();
        if limit.per_node_kbps > 0 {
            let e = self
                .per_node
                .entry((network, node))
                .or_insert_with(|| (0, Bucket::new(limit.per_node_kbps)));
            if e.0 != limit.per_node_kbps {
                *e = (limit.per_node_kbps, Bucket::new(limit.per_node_kbps));
            }
            if !e.1.take(bytes, now) {
                return false;
            }
        }
        if limit.total_kbps > 0 {
            let e = self
                .per_network
                .entry(network)
                .or_insert_with(|| (0, Bucket::new(limit.total_kbps)));
            if e.0 != limit.total_kbps {
                *e = (limit.total_kbps, Bucket::new(limit.total_kbps));
            }
            if !e.1.take(bytes, now) {
                return false;
            }
        }
        true
    }

    fn forget(&mut self, network: NetworkId) {
        self.per_node.retain(|(n, _), _| *n != network);
        self.per_network.remove(&network);
    }
}

impl Inner {
    fn is_primary(&self) -> bool {
        matches!(self.config.role, Role::Primary)
    }

    fn primary_key(&self) -> NodeId {
        match &self.config.role {
            Role::Primary => self.config.keypair.public,
            Role::Replica(p) => p.key,
        }
    }

    /// Lighthouse list for `NetworkInfo`: primary first.
    fn lighthouse_refs(&self, store: &Store) -> Vec<LighthouseRef> {
        let mut v: Vec<LighthouseRef> = store
            .lighthouses_ordered()
            .iter()
            .map(|l| LighthouseRef {
                host: l.host.clone(),
                port: l.port,
                key: l.key,
                name: l.name.clone(),
            })
            .collect();
        if v.is_empty() {
            v.push(LighthouseRef {
                host: self.config.public_host.clone(),
                port: self.config.public_port,
                key: self.config.keypair.public,
                name: self.config.name.clone(),
            });
        }
        v
    }

    fn lighthouse_name(&self, store: &Store, key: &NodeId) -> String {
        store
            .lighthouses
            .get(key)
            .map(|l| l.name.clone())
            .unwrap_or_else(|| key.short())
    }

    fn lighthouse_host(&self, store: &Store, key: &NodeId) -> String {
        store
            .lighthouses
            .get(key)
            .map(|l| l.host.clone())
            .unwrap_or_else(|| self.config.public_host.clone())
    }

    // ---- embedded engine: this lighthouse as an overlay member --------------

    async fn start_engine(self: &Arc<Self>, port: u16) -> anyhow::Result<()> {
        let (engine, mut events) = Engine::start(
            EngineConfig {
                keypair: self.config.keypair.clone(),
                hostname: self.config.name.clone(),
                os: "lighthouse".into(),
                udp_port: 0,
                memberships: Vec::new(),
                persistent_keepalive: Some(25),
                relay_only: false,
                gateway: false,
            },
            Arc::new(NoProtector),
        )
        .await?;
        // Our memberships come back with the Resume reply from ourselves. Use the
        // same name the store lists us under so the engine sees one lighthouse.
        let _ = port;
        engine.connect_lighthouse(ig_core::LighthouseAddr {
            host: self.config.public_host.clone(),
            port: self.config.public_port,
            key: self.config.keypair.public,
        });
        *self.engine.lock() = Some(engine);
        let me = self.clone();
        let t = tokio::spawn(async move {
            while let Some(ev) = events.recv().await {
                if let EngineEvent::MembershipsChanged(list) = ev {
                    me.reconcile_tuns(list.into_iter().map(|m| m.network).collect());
                    me.reconcile_forwards();
                }
            }
        });
        self.tasks.lock().push(t);
        Ok(())
    }

    fn reconcile_tuns(&self, networks: Vec<NetworkInfo>) {
        let engine = self.engine.lock().clone();
        let Some(engine) = engine else { return };
        let mut tuns = self.tuns.lock();
        let wanted: HashMap<NetworkId, NetworkInfo> =
            networks.into_iter().map(|n| (n.id, n)).collect();
        let stale: Vec<NetworkId> = tuns
            .iter()
            .filter(|(id, (cur, _))| {
                wanted.get(id).is_none_or(|w| {
                    w.address != cur.address || w.cidr != cur.cidr || w.address6 != cur.address6
                })
            })
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            engine.detach_tun(TunScope::Network(id));
            tuns.remove(&id);
        }
        let taken: Vec<String> = tuns.values().map(|(_, d)| d.name()).collect();
        for (id, info) in wanted {
            if tuns.contains_key(&id) {
                continue;
            }
            let dev: std::io::Result<Arc<dyn TunDevice>> = match &self.config.overlay {
                Overlay::Off => continue,
                Overlay::Kernel => ig_node::tun::OsTun::create(&info, &taken)
                    .map(|t| Arc::new(t) as Arc<dyn TunDevice>),
                Overlay::Custom(f) => f(&info),
            };
            match dev {
                Ok(dev) => {
                    if let Err(e) = engine.attach_tun(TunScope::Network(id), dev.clone()) {
                        tracing::error!(error = %e, "attach failed");
                        continue;
                    }
                    tracing::info!(network = %info.name, address = %info.address, "lighthouse joined the overlay");
                    tuns.insert(id, (info, dev));
                }
                Err(e) => {
                    tracing::error!(network = %info.name, error = %e, "cannot create tun on the lighthouse")
                }
            }
        }
    }

    // ---- replication ----------------------------------------------------------

    pub fn primary_link_up(&self, tx: mpsc::Sender<ToPrimary>) {
        *self.primary_link.lock() = Some(tx);
    }

    pub fn primary_link_lost(&self) {
        *self.primary_link.lock() = None;
    }

    pub async fn proxy_to_primary(&self, msg: ToPrimary) -> bool {
        let link = self.primary_link.lock().clone();
        match link {
            Some(tx) => tx.send(msg).await.is_ok(),
            None => false,
        }
    }

    /// Replica: adopt the primary's store.
    pub fn apply_snapshot(&self, json: &[u8]) -> anyhow::Result<()> {
        let incoming: Store = serde_json::from_slice(json)?;
        let ids: Vec<NetworkId> = incoming.networks.keys().copied().collect();
        {
            let mut store = self.store.lock();
            *store = incoming;
            self.persist_local(&store);
        }
        tracing::debug!(networks = ids.len(), "snapshot applied");
        self.mark_dirty(ids);
        self.reconcile_forwards();
        Ok(())
    }

    fn push_snapshot(&self, store: &Store) {
        let replicas: Vec<ReplicaLink> = self.replicas.read().values().cloned().collect();
        if replicas.is_empty() {
            return;
        }
        let Ok(json) = serde_json::to_vec(store) else {
            return;
        };
        for l in replicas {
            let _ = l.tx.try_send(FromPrimary::Snapshot {
                store_json: json.clone(),
            });
        }
    }

    fn persist_local(&self, store: &Store) {
        if let Some(p) = &self.config.state_path {
            if let Err(e) = store.save(p) {
                tracing::error!(error = %e, "failed to persist state");
            }
        }
    }

    fn effective_limit(&self, net: &crate::store::Network) -> RelayLimit {
        if net.relay_limit.is_unlimited() {
            self.config.default_relay_limit
        } else {
            net.relay_limit
        }
    }

    fn udp_send(&self, data: &[u8], to: SocketAddr) {
        if !reachable(to, self.dual_stack) {
            return;
        }
        let _ = self.udp.try_send_to(data, to_wire(to, self.dual_stack));
    }

    /// Who should gateway each device right now: the first online candidate in a
    /// fixed order (the admin's `--via` list, or node ids). Deterministic, so every
    /// lighthouse serving the network reaches the same answer from the same
    /// facts; `active_gateways` only remembers the last answer for logging.
    fn resolve_devices(&self, net: &crate::store::Network) -> Vec<DeviceInfo> {
        let sessions = self.sessions.read();
        let mut active = self.active_gateways.lock();
        let mut out = Vec::new();
        for d in net.devices.values() {
            let candidates = self.gateway_candidates(net, d, &sessions);
            let key = (net.id, d.name.clone());
            let chosen = candidates.first().copied();
            match chosen {
                Some(n) => {
                    if active.insert(key, n) != Some(n) {
                        tracing::info!(network = %net.name, device = %d.name, gateway = %n.short(), "gateway selected");
                    }
                }
                None => {
                    if active.remove(&key).is_some() {
                        tracing::warn!(network = %net.name, device = %d.name, "no gateway available");
                    }
                }
            }
            out.push(DeviceInfo {
                name: d.name.clone(),
                dns_name: d.dns_name.clone(),
                address: d.address,
                target: d.target,
                address6: d.address6,
                target6: d.target6,
                gateway: chosen,
            });
        }
        out
    }

    /// Online, gateway-capable members that can reach the device, in preference order.
    fn gateway_candidates(
        &self,
        net: &crate::store::Network,
        d: &crate::store::Device,
        sessions: &HashMap<NodeId, Arc<Session>>,
    ) -> Vec<NodeId> {
        let qualifies = |id: &NodeId, need_subnet: bool| -> bool {
            if !net.members.contains_key(id) {
                return false;
            }
            let Some(s) = sessions.get(id) else {
                return false;
            };
            if !s.gateway {
                return false;
            }
            if !need_subnet {
                return true;
            }
            // On the device's LAN: the IPv4 target's prefix, or the IPv6 target's.
            s.subnets.read().iter().any(|n| n.contains(&d.target))
                || d.target6
                    .is_some_and(|t6| s.subnets6.read().iter().any(|n| n.contains(&t6)))
        };
        if !d.gateways.is_empty() {
            // Explicit list: the admin vouches that these nodes can reach the
            // device, so only membership, presence and capability are checked.
            return d
                .gateways
                .iter()
                .filter(|id| qualifies(id, false))
                .copied()
                .collect();
        }
        let mut v: Vec<NodeId> = net
            .members
            .keys()
            .filter(|id| qualifies(id, true))
            .copied()
            .collect();
        v.sort();
        v
    }

    fn expose(
        &self,
        node: NodeId,
        network: NetworkId,
        proto: ForwardProto,
        public_port: Option<u16>,
        target: &str,
        label: &str,
    ) -> anyhow::Result<ForwardInfo> {
        Self::validate_target(target)?;
        let store = self.store.lock();
        let net = store
            .networks
            .get(&network)
            .ok_or_else(|| anyhow::anyhow!("no such network"))?;
        if !net.members.contains_key(&node) {
            anyhow::bail!("not a member of this network");
        }
        if !net.exposes_allowed {
            anyhow::bail!("network `{}` does not allow ephemeral forwards", net.name);
        }
        let (lo, hi) = self.config.forward_range;
        if lo > hi {
            anyhow::bail!("this lighthouse does not hand out ephemeral ports");
        }
        let mine = self
            .ephemeral
            .lock()
            .iter()
            .filter(|e| e.node == node)
            .count();
        if mine >= MAX_EPHEMERAL_PER_NODE {
            anyhow::bail!("at most {MAX_EPHEMERAL_PER_NODE} ephemeral forwards per node");
        }
        let port = match public_port {
            Some(p) => {
                if p < lo || p > hi {
                    anyhow::bail!("public port must be within {lo}-{hi}");
                }
                if self.port_in_use(&store, p, proto) {
                    anyhow::bail!("public port {p}/{proto} is taken");
                }
                p
            }
            None => (lo..=hi)
                .find(|p| !self.port_in_use(&store, *p, proto))
                .ok_or_else(|| anyhow::anyhow!("no free public port left in {lo}-{hi}"))?,
        };
        let e = Ephemeral {
            id: Self::forward_id(),
            network,
            node,
            proto,
            public_port: port,
            target: target.to_string(),
            label: label.to_string(),
        };
        self.ephemeral.lock().push(e.clone());
        Ok(ForwardInfo {
            id: e.id,
            network,
            node,
            lighthouse: self.config.keypair.public,
            proto,
            kind: ForwardKind::Ephemeral,
            public_host: self.config.public_host.clone(),
            public_port: port,
            target: e.target,
            label: e.label,
        })
    }

    fn network_info(
        &self,
        store: &Store,
        net: &crate::store::Network,
        node: &NodeId,
        m: &crate::store::Member,
    ) -> NetworkInfo {
        NetworkInfo {
            id: net.id,
            name: net.name.clone(),
            cidr: net.cidr,
            address: m.address,
            cidr6: net.cidr6,
            address6: m.address6,
            policy: net.policy.clone(),
            dns_domain: self.config.dns_domain.clone(),
            dns_name: m.dns_name.clone(),
            relay_limit: self.effective_limit(net),
            devices: self.resolve_devices(net),
            forwards: self
                .all_forwards(store)
                .into_iter()
                .filter(|f| f.network == net.id && f.node == *node)
                .collect(),
            exposes_allowed: net.exposes_allowed,
            lighthouses: self.lighthouse_refs(store),
        }
    }

    /// Every forward, permanent and ephemeral, as the node-facing record.
    fn all_forwards(&self, store: &Store) -> Vec<ForwardInfo> {
        let primary = self.primary_key();
        let mut v: Vec<ForwardInfo> = store
            .forwards
            .values()
            .map(|f| {
                let lh = f.lighthouse.unwrap_or(primary);
                ForwardInfo {
                    id: f.id.clone(),
                    network: f.network,
                    node: f.node,
                    lighthouse: lh,
                    proto: f.proto,
                    kind: ForwardKind::Permanent,
                    public_host: self.lighthouse_host(store, &lh),
                    public_port: f.public_port,
                    target: f.target.clone(),
                    label: f.label.clone(),
                }
            })
            .collect();
        v.extend(self.ephemeral.lock().iter().map(|e| ForwardInfo {
            id: e.id.clone(),
            network: e.network,
            node: e.node,
            lighthouse: self.config.keypair.public,
            proto: e.proto,
            kind: ForwardKind::Ephemeral,
            public_host: self.config.public_host.clone(),
            public_port: e.public_port,
            target: e.target.clone(),
            label: e.label.clone(),
        }));
        v
    }

    /// Resolve a forward target (`self:PORT`, `<device>:PORT`, `<ip>:PORT`) to an
    /// overlay socket address for `node` in `network`.
    fn resolve_target(
        store: &Store,
        network: NetworkId,
        node: &NodeId,
        target: &str,
    ) -> Option<SocketAddr> {
        let (host, port) = target.rsplit_once(':')?;
        let host = host.trim_matches(['[', ']']);
        let port: u16 = port.parse().ok()?;
        let net = store.networks.get(&network)?;
        let ip: std::net::IpAddr = if host == "self" {
            std::net::IpAddr::V4(net.members.get(node)?.address)
        } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            ip
        } else {
            std::net::IpAddr::V4(net.devices.get(host)?.address)
        };
        Some(SocketAddr::new(ip, port))
    }

    fn reconcile_forwards(&self) {
        let me = self.config.keypair.public;
        let rules: Vec<ForwardRule> = {
            let store = self.store.lock();
            self.all_forwards(&store)
                .into_iter()
                .filter(|f| f.lighthouse == me)
                .filter_map(|f| {
                    let dst = Self::resolve_target(&store, f.network, &f.node, &f.target)?;
                    Some(ForwardRule {
                        proto: f.proto,
                        public_port: f.public_port,
                        dst,
                    })
                })
                .collect()
        };
        let mut current = self.rules.lock();
        if *current != rules {
            if matches!(self.config.overlay, Overlay::Kernel) {
                ig_node::forward_os::apply(&rules);
            }
            *current = rules;
        }
    }

    fn port_in_use(&self, store: &Store, port: u16, proto: ForwardProto) -> bool {
        port == self.config.listen.port()
            || store.forwards.values().any(|f| {
                f.public_port == port
                    && f.proto == proto
                    && f.lighthouse.unwrap_or(self.primary_key()) == self.config.keypair.public
            })
            || self
                .ephemeral
                .lock()
                .iter()
                .any(|e| e.public_port == port && e.proto == proto)
    }

    fn forward_id() -> String {
        ig_proto::random_array::<4>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn validate_target(target: &str) -> anyhow::Result<()> {
        let (host, port) = target.rsplit_once(':').ok_or_else(|| {
            anyhow::anyhow!("target must be self:PORT, <device>:PORT or <overlay ip>:PORT")
        })?;
        if host.is_empty() || port.parse::<u16>().is_err() {
            anyhow::bail!("target must be self:PORT, <device>:PORT or <overlay ip>:PORT");
        }
        if host == "localhost" || host.starts_with("127.") {
            anyhow::bail!("forwards reach the node over the overlay: use `self:PORT` and bind the service to the overlay address or 0.0.0.0");
        }
        Ok(())
    }

    fn persist(&self, store: &Store) {
        self.persist_local(store);
        if self.is_primary() {
            self.push_snapshot(store);
        }
    }

    fn mark_dirty(&self, nets: impl IntoIterator<Item = NetworkId>) {
        let mut d = self.dirty.lock();
        for n in nets {
            d.insert(n);
        }
        drop(d);
        self.dirty_notify.notify_one();
    }

    fn mark_dirty_for_node(&self, node: &NodeId) {
        let nets = self.store.lock().networks_of(node);
        self.mark_dirty(nets);
    }

    fn endpoints_of(&self, node: &NodeId) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        if let Some(s) = self.sessions.read().get(node) {
            out.extend(s.local_endpoints.read().iter().copied());
        }
        if let Some((addr, when)) = self.udp_addrs.read().get(node) {
            if when.elapsed() < UDP_ADDR_TTL && !out.contains(addr) && !addr.ip().is_loopback() {
                // Public address first: it is the one most likely to work.
                out.insert(0, *addr);
            }
        }
        out
    }

    /// Build the NetworkState for one member. Excludes the member itself.
    fn network_state_for(
        &self,
        store: &Store,
        network: NetworkId,
        me: &NodeId,
    ) -> Option<FromLighthouse> {
        let net = store.networks.get(&network)?;
        let me_member = net.members.get(me)?;
        let sessions = self.sessions.read();
        let peers = net
            .members
            .iter()
            .filter(|(id, _)| *id != me)
            .map(|(id, m)| PeerInfo {
                node: *id,
                hostname: store
                    .nodes
                    .get(id)
                    .map(|n| n.hostname.clone())
                    .unwrap_or_default(),
                dns_name: m.dns_name.clone(),
                address: m.address,
                address6: m.address6,
                endpoints: self.endpoints_of(id),
                online: sessions.contains_key(id),
            })
            .collect();
        Some(FromLighthouse::NetworkState {
            network: self.network_info(store, net, me, me_member),
            peers,
        })
    }

    fn broadcast(&self, network: NetworkId) {
        let store = self.store.lock();
        let Some(net) = store.networks.get(&network) else {
            return;
        };
        let members: Vec<NodeId> = net.members.keys().copied().collect();
        let sessions = self.sessions.read();
        for m in members {
            let Some(s) = sessions.get(&m) else { continue };
            if let Some(msg) = self.network_state_for(&store, network, &m) {
                let _ = s.tx.try_send(msg);
            }
        }
    }

    pub fn send_to(&self, node: &NodeId, msg: FromLighthouse) {
        if let Some(s) = self.sessions.read().get(node) {
            let _ = s.tx.try_send(msg);
        }
    }

    // ---- control messages ---------------------------------------------------

    /// Join on behalf of `node`; the reply is what the node should hear.
    fn apply_join(&self, node: NodeId, network: NetworkId, token: [u8; 16]) -> FromLighthouse {
        let result = {
            let mut store = self.store.lock();
            let r = store.join(network, node, &token);
            if r.is_ok() {
                self.persist(&store);
            }
            r.map(|_| ()).and_then(|_| {
                self.network_info_for(&store, network, &node)
                    .ok_or(StoreError::NotMember)
            })
        };
        match result {
            Ok(info) => {
                tracing::info!(node = %node.short(), network = %info.name, address = %info.address, "node joined");
                self.mark_dirty([network]);
                FromLighthouse::Joined { network: info }
            }
            Err(e) => {
                tracing::info!(node = %node.short(), %network, error = %e, "join refused");
                FromLighthouse::JoinFailed {
                    network,
                    reason: e.to_string(),
                }
            }
        }
    }

    fn apply_leave(&self, node: NodeId, network: NetworkId) -> FromLighthouse {
        let mut store = self.store.lock();
        if store.remove_member(network, &node).is_ok() {
            self.persist(&store);
            tracing::info!(node = %node.short(), %network, "node left");
        }
        drop(store);
        self.mark_dirty([network]);
        FromLighthouse::Left { network }
    }

    fn handle_control(self: &Arc<Self>, session: &Arc<Session>, msg: ToLighthouse) {
        let node = session.node;
        *session.last_seen.lock() = Instant::now();
        if !self.is_primary() {
            // Only the primary writes the store. Joins and leaves are proxied; the
            // reply comes back over the replication link and is relayed to the node.
            if matches!(msg, ToLighthouse::Join { .. } | ToLighthouse::Leave { .. }) {
                let me = self.clone();
                let s = session.clone();
                tokio::spawn(async move {
                    let proxied = ToPrimary::Proxy {
                        node,
                        hostname: s.hostname.clone(),
                        os: s.os.clone(),
                        msg: msg.clone(),
                    };
                    if !me.proxy_to_primary(proxied).await {
                        let reply = match msg {
                            ToLighthouse::Join { network, .. } => FromLighthouse::JoinFailed {
                                network,
                                reason: "the primary lighthouse is unreachable; joins wait until it is back".into(),
                            },
                            ToLighthouse::Leave { network } => FromLighthouse::Left { network },
                            _ => return,
                        };
                        let _ = s.tx.try_send(reply);
                    }
                });
                return;
            }
        }
        match msg {
            ToLighthouse::Join { network, token } => {
                let reply = self.apply_join(node, network, token);
                let _ = session.tx.try_send(reply);
            }
            ToLighthouse::Leave { network } => {
                let reply = self.apply_leave(node, network);
                let _ = session.tx.try_send(reply);
            }
            ToLighthouse::Resume => {
                let store = self.store.lock();
                for net in store.networks_of(&node) {
                    if let Some(msg) = self.network_state_for(&store, net, &node) {
                        let _ = session.tx.try_send(msg);
                    }
                }
            }
            ToLighthouse::Endpoints {
                local,
                subnets,
                subnets6,
            } => {
                let mut local: Vec<SocketAddr> = local.into_iter().take(10).collect();
                local.dedup();
                let subnets: Vec<Ipv4Net> = subnets.into_iter().take(16).collect();
                let subnets6: Vec<ipnet::Ipv6Net> = subnets6.into_iter().take(16).collect();
                let changed = *session.local_endpoints.read() != local
                    || *session.subnets.read() != subnets
                    || *session.subnets6.read() != subnets6;
                if changed {
                    *session.local_endpoints.write() = local;
                    *session.subnets.write() = subnets;
                    *session.subnets6.write() = subnets6;
                    self.mark_dirty_for_node(&node);
                }
            }
            ToLighthouse::Punch { network, target } => {
                let ok = {
                    let store = self.store.lock();
                    store.networks.get(&network).is_some_and(|n| {
                        n.members.contains_key(&node) && n.members.contains_key(&target)
                    })
                };
                if ok {
                    let endpoints = self.endpoints_of(&node);
                    self.send_to(
                        &target,
                        FromLighthouse::PunchRequest {
                            network,
                            from: node,
                            endpoints,
                        },
                    );
                }
            }
            ToLighthouse::Ping { nonce } => {
                let _ = session.tx.try_send(FromLighthouse::Pong { nonce });
            }
            ToLighthouse::Expose {
                network,
                proto,
                public_port,
                target,
                label,
            } => match self.expose(node, network, proto, public_port, &target, &label) {
                Ok(info) => {
                    tracing::info!(node = %node.short(), port = info.public_port, proto = %proto, %target, "ephemeral forward");
                    let _ = session
                        .tx
                        .try_send(FromLighthouse::Exposed { forward: info });
                    self.reconcile_forwards();
                    self.mark_dirty([network]);
                }
                Err(e) => {
                    let _ = session.tx.try_send(FromLighthouse::ExposeFailed {
                        target,
                        reason: e.to_string(),
                    });
                }
            },
            ToLighthouse::Unexpose { id } => {
                let removed: Vec<Ephemeral> = {
                    let mut eph = self.ephemeral.lock();
                    let (gone, keep): (Vec<_>, Vec<_>) =
                        eph.drain(..).partition(|e| e.id == id && e.node == node);
                    *eph = keep;
                    gone
                };
                for e in removed {
                    let _ = session
                        .tx
                        .try_send(FromLighthouse::Unexposed { id: e.id.clone() });
                    self.reconcile_forwards();
                    self.mark_dirty([e.network]);
                }
            }
        }
    }

    fn network_info_for(
        &self,
        store: &Store,
        network: NetworkId,
        node: &NodeId,
    ) -> Option<NetworkInfo> {
        let net = store.networks.get(&network)?;
        let m = net.members.get(node)?;
        Some(self.network_info(store, net, node, m))
    }

    // ---- udp ------------------------------------------------------------------

    fn handle_udp(&self, data: &[u8], from: SocketAddr) {
        let Some(frame) = disco::decode(data) else {
            return;
        };
        match frame {
            disco::Disco::Probe { node, ts } => {
                let Some(session) = self.sessions.read().get(&node).cloned() else {
                    return;
                };
                if !disco::verify_mac(data, &session.token) {
                    tracing::debug!(%from, node = %node.short(), "probe with bad mac");
                    return;
                }
                let changed = {
                    let mut addrs = self.udp_addrs.write();
                    let prev = addrs.insert(node, (from, Instant::now()));
                    prev.map(|(a, _)| a) != Some(from)
                };
                if changed {
                    let mut rev = self.udp_nodes.write();
                    rev.retain(|_, n| *n != node);
                    rev.insert(from, node);
                    drop(rev);
                    tracing::debug!(node = %node.short(), %from, "udp endpoint");
                    self.mark_dirty_for_node(&node);
                }
                let reply = disco::encode_probe_reply(ts, from, &session.token);
                self.udp_send(&reply, from);
            }
            disco::Disco::Relay {
                network,
                dst,
                payload,
            } => {
                if payload.len() > MAX_RELAY_PAYLOAD {
                    return;
                }
                let Some(src) = self.udp_nodes.read().get(&from).copied() else {
                    tracing::trace!(%from, "relay from unknown address");
                    return;
                };
                let dst_addr = {
                    let addrs = self.udp_addrs.read();
                    match addrs.get(&dst) {
                        Some((a, when)) if when.elapsed() < UDP_ADDR_TTL => *a,
                        _ => return,
                    }
                };
                let limit = {
                    let store = self.store.lock();
                    let Some(net) = store.networks.get(&network) else {
                        return;
                    };
                    if !(net.members.contains_key(&src) && net.members.contains_key(&dst)) {
                        return;
                    }
                    self.effective_limit(net)
                };
                if !self
                    .buckets
                    .lock()
                    .allow(network, src, limit, payload.len())
                {
                    tracing::trace!(%network, node = %src.short(), "relay rate limited");
                    return;
                }
                let frame = disco::encode_relayed(&src, payload);
                self.udp_send(&frame, dst_addr);
            }
            _ => {}
        }
    }

    // ---- admin ------------------------------------------------------------------

    fn admin(&self, req: AdminRequest) -> AdminResponse {
        match self.admin_inner(req) {
            Ok(r) => r,
            Err(e) => AdminResponse::Error {
                message: e.to_string(),
            },
        }
    }

    fn admin_inner(&self, req: AdminRequest) -> anyhow::Result<AdminResponse> {
        let read_only = matches!(
            req,
            AdminRequest::Info
                | AdminRequest::NetworkList
                | AdminRequest::InviteList { .. }
                | AdminRequest::NodeList { .. }
                | AdminRequest::DeviceList { .. }
                | AdminRequest::ForwardList
                | AdminRequest::LighthouseList
        );
        if let (Role::Replica(p), false) = (&self.config.role, read_only) {
            anyhow::bail!(
                "this lighthouse is a replica; run admin changes on the primary at {}:{}",
                p.host,
                p.port
            );
        }
        match req {
            AdminRequest::LighthouseAdd {
                name,
                host,
                port,
                key,
            } => {
                let mut store = self.store.lock();
                if key == self.config.keypair.public {
                    anyhow::bail!("that is this lighthouse's own key");
                }
                store.add_lighthouse(crate::store::LighthouseRecord {
                    key,
                    name,
                    host,
                    port,
                    primary: false,
                })?;
                self.persist(&store);
                let ids: Vec<NetworkId> = store.networks.keys().copied().collect();
                let list = self.lighthouse_summaries(&store);
                drop(store);
                self.mark_dirty(ids);
                Ok(AdminResponse::Lighthouses(list))
            }
            AdminRequest::LighthouseList => {
                let store = self.store.lock();
                Ok(AdminResponse::Lighthouses(
                    self.lighthouse_summaries(&store),
                ))
            }
            AdminRequest::LighthouseRemove { key } => {
                if key == self.config.keypair.public {
                    anyhow::bail!("cannot remove the primary itself");
                }
                let mut store = self.store.lock();
                store.remove_lighthouse(&key)?;
                self.persist(&store);
                let ids: Vec<NetworkId> = store.networks.keys().copied().collect();
                drop(store);
                if let Some(l) = self.replicas.write().remove(&key) {
                    l.abort.notify_one();
                }
                self.mark_dirty(ids);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::Info => {
                let store = self.store.lock();
                Ok(AdminResponse::Info(LighthouseInfo {
                    public_key: self.config.keypair.public,
                    public_host: self.config.public_host.clone(),
                    port: self.config.public_port,
                    networks: store.networks.len(),
                    nodes_online: self.sessions.read().len(),
                    uptime_secs: self.started.elapsed().as_secs(),
                    dns_domain: self.config.dns_domain.clone(),
                    role: match &self.config.role {
                        Role::Primary => "primary".into(),
                        Role::Replica(p) => format!("replica of {}:{}", p.host, p.port),
                    },
                    overlay: self
                        .engine
                        .lock()
                        .as_ref()
                        .map(|e| {
                            e.status()
                                .networks
                                .iter()
                                .map(|n| (n.info.name.clone(), n.info.address.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                }))
            }
            AdminRequest::NetworkCreate { name, cidr, cidr6 } => {
                let mut store = self.store.lock();
                let net = store.create_network(&name, cidr, cidr6)?;
                let summary = self.summarise(net);
                self.persist(&store);
                Ok(AdminResponse::Networks(vec![summary]))
            }
            AdminRequest::NetworkList => {
                let store = self.store.lock();
                Ok(AdminResponse::Networks(
                    store.networks.values().map(|n| self.summarise(n)).collect(),
                ))
            }
            AdminRequest::NetworkDelete { network } => {
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                let net = store.networks.remove(&id).expect("resolved");
                self.persist(&store);
                drop(store);
                self.buckets.lock().forget(id);
                for m in net.members.keys() {
                    self.send_to(
                        m,
                        FromLighthouse::Removed {
                            network: id,
                            reason: "network deleted".into(),
                        },
                    );
                }
                Ok(AdminResponse::Ok)
            }
            AdminRequest::NetworkSetPolicy { network, policy } => {
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                store.networks.get_mut(&id).expect("resolved").policy = policy;
                self.persist(&store);
                drop(store);
                self.mark_dirty([id]);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::NetworkSetRelayLimit { network, limit } => {
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                store.networks.get_mut(&id).expect("resolved").relay_limit = limit;
                self.persist(&store);
                drop(store);
                self.buckets.lock().forget(id);
                self.mark_dirty([id]);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::InviteCreate {
                network,
                uses,
                ttl_secs,
                label,
            } => {
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                let token: [u8; 16] = ig_proto::random_array();
                let invite_id: String = ig_proto::random_array::<4>()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let net = store.networks.get_mut(&id).expect("resolved");
                net.invites.push(InviteRecord {
                    id: invite_id.clone(),
                    label,
                    token_hash: Invite::token_hash(&token),
                    uses_left: uses.max(1),
                    expires_at: now_secs() + ttl_secs.max(60),
                });
                let invite = Invite {
                    host: self.config.public_host.clone(),
                    port: self.config.public_port,
                    lighthouse: self.config.keypair.public,
                    network: id,
                    network_name: net.name.clone(),
                    token,
                    extra_lighthouses: self
                        .lighthouse_refs(&store)
                        .into_iter()
                        .filter(|l| l.key != self.config.keypair.public)
                        .collect(),
                };
                self.persist(&store);
                Ok(AdminResponse::Invite {
                    invite: invite.encode(),
                    invite_id,
                })
            }
            AdminRequest::InviteList { network } => {
                let store = self.store.lock();
                let id = store.resolve(&network)?;
                let list = store.networks[&id]
                    .invites
                    .iter()
                    .map(|i| InviteSummary {
                        id: i.id.clone(),
                        label: i.label.clone(),
                        uses_left: i.uses_left,
                        expires_at: i.expires_at,
                    })
                    .collect();
                Ok(AdminResponse::Invites(list))
            }
            AdminRequest::InviteRevoke { network, invite_id } => {
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                let net = store.networks.get_mut(&id).expect("resolved");
                let before = net.invites.len();
                net.invites.retain(|i| i.id != invite_id);
                if net.invites.len() == before {
                    return Err(StoreError::NoSuchInvite(invite_id).into());
                }
                self.persist(&store);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::NodeList { network } => {
                let store = self.store.lock();
                let filter = match network {
                    Some(n) => Some(store.resolve(&n)?),
                    None => None,
                };
                let sessions = self.sessions.read();
                let now = now_secs();
                let mut out = Vec::new();
                for net in store.networks.values() {
                    if filter.is_some_and(|f| f != net.id) {
                        continue;
                    }
                    for (id, m) in &net.members {
                        let rec = store.nodes.get(id).cloned().unwrap_or_default();
                        let online = sessions.contains_key(id);
                        out.push(NodeSummary {
                            node: *id,
                            hostname: rec.hostname,
                            os: rec.os,
                            network: net.id,
                            network_name: net.name.clone(),
                            dns_name: m.dns_name.clone(),
                            address: m.address,
                            address6: m.address6,
                            online,
                            endpoints: self.endpoints_of(id),
                            last_seen_secs_ago: if online {
                                Some(0)
                            } else if rec.last_seen > 0 {
                                Some(now.saturating_sub(rec.last_seen))
                            } else {
                                None
                            },
                        });
                    }
                }
                Ok(AdminResponse::Nodes(out))
            }
            AdminRequest::DeviceAdd {
                network,
                name,
                target,
                target6,
                gateways,
            } => {
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                let label = ig_proto::control::dns_label(&name);
                if label != name.to_ascii_lowercase() || name.is_empty() {
                    anyhow::bail!("device names use letters, digits and dashes only");
                }
                if target6.is_some() && store.networks[&id].cidr6.is_none() {
                    anyhow::bail!("network has no IPv6 prefix; create it with --ipv6 to register IPv6 devices");
                }
                let dev = store.add_device(id, &name, target, target6, gateways)?;
                self.persist(&store);
                let summary = self.device_summary(&store, id, &dev);
                drop(store);
                self.mark_dirty([id]);
                Ok(AdminResponse::Devices(vec![summary]))
            }
            AdminRequest::DeviceList { network } => {
                let store = self.store.lock();
                let id = store.resolve(&network)?;
                let list = store.networks[&id]
                    .devices
                    .values()
                    .map(|d| self.device_summary(&store, id, d))
                    .collect();
                Ok(AdminResponse::Devices(list))
            }
            AdminRequest::DeviceRemove { network, name } => {
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                store.remove_device(id, &name)?;
                self.persist(&store);
                drop(store);
                self.active_gateways.lock().remove(&(id, name));
                self.mark_dirty([id]);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::ForwardAdd {
                network,
                node,
                proto,
                public_port,
                target,
                label,
                lighthouse,
            } => {
                Self::validate_target(&target)?;
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                let publisher = lighthouse.unwrap_or(self.primary_key());
                if !store.lighthouses.contains_key(&publisher) {
                    anyhow::bail!("unknown lighthouse {}", publisher.short());
                }
                if Self::resolve_target(&store, id, &node, &target).is_none() {
                    anyhow::bail!("target `{target}` does not resolve in that network (use self:PORT or a device name)");
                }
                if !store.networks[&id].members.contains_key(&node) {
                    anyhow::bail!("node is not a member of that network");
                }
                if public_port < 1024 && public_port != 80 && public_port != 443 {
                    anyhow::bail!("public port must be 80, 443 or 1024 and above");
                }
                let taken = store.forwards.values().any(|f| {
                    f.public_port == public_port
                        && f.proto == proto
                        && f.lighthouse.unwrap_or(self.primary_key()) == publisher
                });
                if taken
                    || (publisher == self.config.keypair.public
                        && self.port_in_use(&store, public_port, proto))
                {
                    anyhow::bail!("public port {public_port}/{proto} is taken on that lighthouse");
                }
                let fid = Self::forward_id();
                store.forwards.insert(
                    fid.clone(),
                    crate::store::ForwardRecord {
                        id: fid.clone(),
                        network: id,
                        node,
                        proto,
                        public_port,
                        target,
                        label,
                        lighthouse: Some(publisher),
                        created_at: now_secs(),
                    },
                );
                self.persist(&store);
                let list = self
                    .forward_summaries(&store)
                    .into_iter()
                    .filter(|f| f.info.id == fid)
                    .collect();
                drop(store);
                self.reconcile_forwards();
                self.mark_dirty([id]);
                Ok(AdminResponse::Forwards(list))
            }
            AdminRequest::ForwardList => {
                let store = self.store.lock();
                Ok(AdminResponse::Forwards(self.forward_summaries(&store)))
            }
            AdminRequest::ForwardRemove { id } => {
                let mut store = self.store.lock();
                let net = match store.forwards.remove(&id) {
                    Some(f) => {
                        self.persist(&store);
                        f.network
                    }
                    None => {
                        let mut eph = self.ephemeral.lock();
                        let Some(pos) = eph.iter().position(|e| e.id == id) else {
                            anyhow::bail!("forward not found: {id}");
                        };
                        let e = eph.remove(pos);
                        self.send_to(&e.node, FromLighthouse::Unexposed { id: e.id.clone() });
                        e.network
                    }
                };
                drop(store);
                self.reconcile_forwards();
                self.mark_dirty([net]);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::NetworkSetExposes { network, allowed } => {
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                store
                    .networks
                    .get_mut(&id)
                    .expect("resolved")
                    .exposes_allowed = allowed;
                self.persist(&store);
                drop(store);
                self.mark_dirty([id]);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::NodeRemove { network, node } => {
                let mut store = self.store.lock();
                let id = store.resolve(&network)?;
                store.remove_member(id, &node)?;
                self.persist(&store);
                drop(store);
                self.send_to(
                    &node,
                    FromLighthouse::Removed {
                        network: id,
                        reason: "removed by admin".into(),
                    },
                );
                self.mark_dirty([id]);
                Ok(AdminResponse::Ok)
            }
        }
    }

    fn device_summary(
        &self,
        store: &Store,
        id: NetworkId,
        d: &crate::store::Device,
    ) -> DeviceSummary {
        let net = &store.networks[&id];
        let active = self
            .resolve_devices(net)
            .into_iter()
            .find(|x| x.name == d.name)
            .and_then(|x| x.gateway);
        let sessions = self.sessions.read();
        let candidates = self.gateway_candidates(net, d, &sessions);
        let hostname = |n: &NodeId| {
            store
                .nodes
                .get(n)
                .map(|r| r.hostname.clone())
                .unwrap_or_default()
        };
        DeviceSummary {
            network: id,
            network_name: net.name.clone(),
            name: d.name.clone(),
            dns_name: d.dns_name.clone(),
            address: d.address,
            target: d.target,
            address6: d.address6,
            target6: d.target6,
            gateways: d.gateways.clone(),
            active: active.map(|n| (n, hostname(&n))),
            candidates: candidates
                .iter()
                .map(|n| format!("{} ({})", hostname(n), n.short()))
                .collect(),
        }
    }

    fn forward_summaries(&self, store: &Store) -> Vec<ForwardSummary> {
        let sessions = self.sessions.read();
        self.all_forwards(store)
            .into_iter()
            .map(|info| ForwardSummary {
                network_name: store
                    .networks
                    .get(&info.network)
                    .map(|n| n.name.clone())
                    .unwrap_or_default(),
                node_hostname: store
                    .nodes
                    .get(&info.node)
                    .map(|n| n.hostname.clone())
                    .unwrap_or_default(),
                node_online: sessions.contains_key(&info.node),
                lighthouse_name: self.lighthouse_name(store, &info.lighthouse),
                info,
            })
            .collect()
    }

    fn lighthouse_summaries(&self, store: &Store) -> Vec<ig_proto::admin::LighthouseSummary> {
        let replicas = self.replicas.read();
        store
            .lighthouses_ordered()
            .into_iter()
            .map(|l| ig_proto::admin::LighthouseSummary {
                connected: l.key == self.config.keypair.public
                    || replicas.contains_key(&l.key)
                    || (l.key == self.primary_key() && self.primary_link.lock().is_some()),
                name: l.name,
                host: l.host,
                port: l.port,
                key: l.key,
                primary: l.primary,
            })
            .collect()
    }

    fn summarise(&self, n: &crate::store::Network) -> NetworkSummary {
        let sessions = self.sessions.read();
        NetworkSummary {
            id: n.id,
            name: n.name.clone(),
            cidr: n.cidr,
            cidr6: n.cidr6,
            members: n.members.len(),
            online: n
                .members
                .keys()
                .filter(|m| sessions.contains_key(m))
                .count(),
            policy: n.policy.clone(),
            relay_limit: self.effective_limit(n),
            exposes_allowed: n.exposes_allowed,
        }
    }
}

async fn accept_loop(inner: Arc<Inner>, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, from)) => {
                let inner = inner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(inner, stream, from).await {
                        tracing::debug!(%from, error = %e, "control connection ended");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_connection(
    inner: Arc<Inner>,
    stream: TcpStream,
    from: SocketAddr,
) -> anyhow::Result<()> {
    let _ = stream.set_nodelay(true);
    let token: [u8; 32] = ig_proto::random_array();
    let priv_key = inner.config.keypair.private.0;
    let (noise, hello): (NoiseStream<TcpStream>, ClientHello) = tokio::time::timeout(
        Duration::from_secs(10),
        NoiseStream::accept(stream, &priv_key, |_node, _hello: &ClientHello| {
            ServerHello {
                version: PROTOCOL_VERSION,
                session_token: token,
                server_time: now_secs(),
            }
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("handshake timed out"))??;
    if hello.version != PROTOCOL_VERSION {
        anyhow::bail!("node speaks protocol v{}", hello.version);
    }
    let node = noise.remote();
    if hello.replica {
        return handle_replica(inner, noise, node).await;
    }
    let (tx, mut rx) = mpsc::channel::<FromLighthouse>(256);
    let session = Arc::new(Session {
        node,
        hostname: hello.hostname.clone(),
        os: hello.os.clone(),
        token,
        tx,
        local_endpoints: RwLock::new(Vec::new()),
        subnets: RwLock::new(Vec::new()),
        subnets6: RwLock::new(Vec::new()),
        gateway: hello.gateway,
        last_seen: Mutex::new(Instant::now()),
        abort: tokio::sync::Notify::new(),
    });
    {
        let mut store = inner.store.lock();
        store.touch_node(node, &hello.hostname, &hello.os);
        let relabelled = store.refresh_labels(&node);
        inner.persist(&store);
        drop(store);
        inner.mark_dirty(relabelled);
    }
    if let Some(old) = inner.sessions.write().insert(node, session.clone()) {
        tracing::info!(node = %node.short(), "replacing existing session");
        old.abort.notify_one();
    }
    inner.mark_dirty_for_node(&node);
    tracing::info!(node = %node.short(), hostname = %hello.hostname, os = %hello.os, gateway = hello.gateway, %from, "node connected");

    let (mut noise_tx, mut noise_rx) = noise.into_parts();
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if noise_tx.send(&msg).await.is_err() {
                break;
            }
        }
    });

    let result: anyhow::Result<()> = async {
        loop {
            tokio::select! {
                _ = session.abort.notified() => break Ok(()),
                msg = noise_rx.recv::<ToLighthouse>() => {
                    let msg = msg?;
                    inner.handle_control(&session, msg);
                }
            }
        }
    }
    .await;

    writer.abort();
    {
        let mut sessions = inner.sessions.write();
        if sessions
            .get(&node)
            .is_some_and(|s| Arc::ptr_eq(s, &session))
        {
            sessions.remove(&node);
        }
    }
    {
        let mut store = inner.store.lock();
        if let Some(rec) = store.nodes.get_mut(&node) {
            rec.last_seen = now_secs();
        }
        inner.persist(&store);
    }
    // Ephemeral forwards live only as long as the session.
    let still_here = inner.sessions.read().contains_key(&node);
    if !still_here {
        let gone: Vec<Ephemeral> = {
            let mut eph = inner.ephemeral.lock();
            let (g, keep): (Vec<_>, Vec<_>) = eph.drain(..).partition(|e| e.node == node);
            *eph = keep;
            g
        };
        if !gone.is_empty() {
            inner.reconcile_forwards();
            inner.mark_dirty(gone.iter().map(|e| e.network));
        }
    }
    inner.mark_dirty_for_node(&node);
    tracing::info!(node = %node.short(), "node disconnected");
    result
}

/// A registered replica: stream snapshots to it and serve its proxied writes.
async fn handle_replica(
    inner: Arc<Inner>,
    noise: NoiseStream<TcpStream>,
    node: NodeId,
) -> anyhow::Result<()> {
    if !inner.is_primary() {
        anyhow::bail!("replication link to a replica");
    }
    let known = inner.store.lock().lighthouses.contains_key(&node);
    if !known {
        anyhow::bail!(
            "replica {} is not registered (ig-lighthouse lighthouse add ...)",
            node.short()
        );
    }
    let (tx, mut rx) = mpsc::channel::<FromPrimary>(64);
    let abort = Arc::new(tokio::sync::Notify::new());
    let link = ReplicaLink {
        tx: tx.clone(),
        abort: abort.clone(),
    };
    if let Some(old) = inner.replicas.write().insert(node, link) {
        old.abort.notify_one();
    }
    tracing::info!(replica = %node.short(), "replica connected");
    {
        let store = inner.store.lock();
        let json = serde_json::to_vec(&*store)?;
        let _ = tx.try_send(FromPrimary::Snapshot { store_json: json });
    }
    let (mut noise_tx, mut noise_rx) = noise.into_parts();
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if noise_tx.send(&m).await.is_err() {
                break;
            }
        }
    });
    let result: anyhow::Result<()> = async {
        loop {
            let msg = tokio::select! {
                _ = abort.notified() => break Ok(()),
                m = noise_rx.recv::<ToPrimary>() => m?,
            };
            match msg {
                ToPrimary::Ping => {
                    let _ = tx.try_send(FromPrimary::Pong);
                }
                ToPrimary::Proxy {
                    node: for_node,
                    hostname,
                    os,
                    msg,
                } => {
                    {
                        let mut store = inner.store.lock();
                        store.touch_node(for_node, &hostname, &os);
                        let relabelled = store.refresh_labels(&for_node);
                        drop(store);
                        inner.mark_dirty(relabelled);
                    }
                    let reply = match msg {
                        ToLighthouse::Join { network, token } => {
                            Some(inner.apply_join(for_node, network, token))
                        }
                        ToLighthouse::Leave { network } => {
                            Some(inner.apply_leave(for_node, network))
                        }
                        _ => None,
                    };
                    if let Some(reply) = reply {
                        let _ = tx.try_send(FromPrimary::ProxyReply {
                            node: for_node,
                            msg: reply,
                        });
                    }
                }
            }
        }
    }
    .await;
    writer.abort();
    {
        let mut r = inner.replicas.write();
        if r.get(&node).is_some_and(|cur| cur.tx.same_channel(&tx)) {
            r.remove(&node);
        }
    }
    tracing::info!(replica = %node.short(), "replica disconnected");
    result
}

async fn udp_loop(inner: Arc<Inner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        match inner.udp.recv_from(&mut buf).await {
            Ok((n, from)) => inner.handle_udp(&buf[..n], canonical(from)),
            Err(e) => {
                tracing::warn!(error = %e, "udp receive error");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn broadcast_loop(inner: Arc<Inner>) {
    loop {
        inner.dirty_notify.notified().await;
        tokio::time::sleep(BROADCAST_DEBOUNCE).await;
        let nets: Vec<NetworkId> = inner.dirty.lock().drain().collect();
        for n in nets {
            inner.broadcast(n);
        }
    }
}

/// Drop control sessions that went silent so their networks learn quickly.
async fn reap_idle_sessions(inner: Arc<Inner>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let idle: Vec<Arc<Session>> = inner
            .sessions
            .read()
            .values()
            .filter(|s| s.last_seen.lock().elapsed() > SESSION_IDLE)
            .cloned()
            .collect();
        for s in idle {
            tracing::info!(node = %s.node.short(), "control session idle, dropping");
            s.abort.notify_one();
        }
    }
}

async fn housekeeping(inner: Arc<Inner>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        {
            let mut store = inner.store.lock();
            if store.prune_invites() {
                inner.persist(&store);
            }
        }
        // Forget stale UDP addresses so peers stop trying dead endpoints.
        let stale: Vec<NodeId> = inner
            .udp_addrs
            .read()
            .iter()
            .filter(|(_, (_, when))| when.elapsed() > UDP_ADDR_TTL * 2)
            .map(|(n, _)| *n)
            .collect();
        if !stale.is_empty() {
            let mut addrs = inner.udp_addrs.write();
            let mut rev = inner.udp_nodes.write();
            for n in &stale {
                if let Some((a, _)) = addrs.remove(n) {
                    rev.remove(&a);
                }
            }
        }
    }
}
