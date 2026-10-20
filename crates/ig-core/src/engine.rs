//! The engine: UDP socket, peer table, TUN attachments and the glue between them.

use crate::control::{self, ControlCmd, LighthouseHandle};
use crate::dns::DnsTable;
use crate::filter::PeerFilter;
use crate::packet;
use crate::peer::Peer;
use crate::state::{LighthouseAddr, Membership};
use crate::tun::{TunDevice, TunScope};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ig_proto::control::{NetworkInfo, PeerInfo};
use ig_proto::ipc::{NetworkStatus, PeerStatus, StatusReport};
use ig_proto::udp::{bind_dual_stack, canonical, reachable, to_wire};
use ig_proto::{disco, Invite, Keypair, NetworkId, NodeId};
use ipnet::{Ipv4Net, Ipv6Net};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const TIMER_TICK: Duration = Duration::from_millis(250);
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);
const LEAVE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PACKET: usize = 65536;
const OUT_BUF: usize = MAX_PACKET + 128;

/// Hook for platforms that must exempt the engine's sockets from their own VPN
/// (Android `VpnService.protect`). Receives the raw fd (unix) or SOCKET (Windows).
pub trait SocketProtector: Send + Sync {
    fn protect(&self, raw_socket: i64);
}

/// Default protector that does nothing.
pub struct NoProtector;
impl SocketProtector for NoProtector {
    fn protect(&self, _raw_socket: i64) {}
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub keypair: Keypair,
    pub hostname: String,
    /// Free-form OS tag shown to admins ("linux", "windows", "android").
    pub os: String,
    /// UDP port for WireGuard traffic. 0 picks a random port.
    pub udp_port: u16,
    /// Networks joined earlier; resumed on start.
    pub memberships: Vec<Membership>,
    /// WireGuard persistent keepalive in seconds. Keeps NAT mappings warm.
    pub persistent_keepalive: Option<u16>,
    /// Never try direct paths; send everything through lighthouse relays.
    /// Useful for diagnostics and for hosts that must not expose their address.
    pub relay_only: bool,
    /// Offer to act as a gateway for devices registered on this host's LANs.
    pub gateway: bool,
}

#[derive(Clone, Debug)]
pub enum EngineEvent {
    /// The set of joined networks (or an address inside one) changed. The
    /// embedder persists the list and reconciles TUN devices against it.
    MembershipsChanged(Vec<Membership>),
    /// Peer table changed (informational, for UIs).
    PeersChanged,
    LighthouseStatus {
        lighthouse: LighthouseAddr,
        connected: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("join rejected: {0}")]
    JoinRejected(String),
    #[error("join timed out{0}")]
    JoinTimeout(String),
    #[error("not a member of network {0}")]
    UnknownNetwork(NetworkId),
    #[error("{0}")]
    Refused(String),
    #[error("lighthouse did not answer in time")]
    NoReply,
    #[error("engine is shutting down")]
    Stopped,
}

struct TunAttachment {
    dev: Arc<dyn TunDevice>,
    task: JoinHandle<()>,
}

impl Drop for TunAttachment {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct NetworkEntry {
    membership: Membership,
    tun: Option<TunAttachment>,
}

#[derive(Default)]
struct PeerTable {
    by_id: HashMap<NodeId, Arc<Mutex<Peer>>>,
    by_index: HashMap<u32, NodeId>,
    by_addr: HashMap<IpAddr, NodeId>,
    next_index: u32,
}

impl PeerTable {
    fn rebuild_routes(&mut self) {
        self.by_addr.clear();
        for (id, p) in &self.by_id {
            let p = p.lock();
            for addr in p.addresses.values().flatten() {
                if let Some(other) = self.by_addr.insert(*addr, *id) {
                    if other != *id {
                        tracing::warn!(%addr, "overlay address used by two peers; networks have overlapping CIDRs");
                    }
                }
            }
        }
    }
}

pub struct Inner {
    pub keypair: Keypair,
    secret: StaticSecret,
    public: PublicKey,
    pub hostname: String,
    pub os: String,
    udp: UdpSocket,
    /// True when the socket is IPv6 with IPv4-mapped addresses enabled.
    dual_stack: bool,
    udp_port: u16,
    /// Peer and own names for the in-engine DNS responder.
    dns: RwLock<DnsTable>,
    keepalive: Option<u16>,
    relay_only: bool,
    pub gateway: bool,
    peers: RwLock<PeerTable>,
    networks: RwLock<HashMap<NetworkId, NetworkEntry>>,
    lighthouses: Mutex<HashMap<LighthouseAddr, Arc<LighthouseHandle>>>,
    catch_all: RwLock<Option<TunAttachment>>,
    events: mpsc::Sender<EngineEvent>,
    protector: Arc<dyn SocketProtector>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Ephemeral forwards we asked for, re-requested after a reconnect.
    exposes: Mutex<Vec<(LighthouseAddr, ExposeRequest)>>,
    /// Joins in flight: network -> every lighthouse named by the invite, so the
    /// membership records all of them when `Joined` arrives.
    pending_joins: Mutex<HashMap<NetworkId, Vec<LighthouseAddr>>>,
    /// Back-reference so `&self` methods can spawn control tasks.
    me: Mutex<std::sync::Weak<Inner>>,
}

/// An ephemeral forward as the node remembers it.
#[derive(Clone, Debug)]
pub struct ExposeRequest {
    pub id: String,
    pub network: NetworkId,
    pub proto: ig_proto::tunnel::ForwardProto,
    pub public_port: u16,
    pub target: String,
    pub label: String,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

impl Engine {
    /// Bind the UDP socket, resume memberships and start background tasks.
    pub async fn start(
        config: EngineConfig,
        protector: Arc<dyn SocketProtector>,
    ) -> Result<(Engine, mpsc::Receiver<EngineEvent>), EngineError> {
        let (udp, dual_stack) =
            bind_dual_stack(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), config.udp_port)?;
        protect(&*protector, &udp);
        let udp_port = udp.local_addr()?.port();
        let secret = config.keypair.private.to_static_secret();
        let public = PublicKey::from(&secret);
        let (events, events_rx) = mpsc::channel(256);

        let mut networks = HashMap::new();
        let mut by_lighthouse: HashMap<LighthouseAddr, Vec<NetworkId>> = HashMap::new();
        for m in &config.memberships {
            for lh in m.lighthouses() {
                by_lighthouse.entry(lh).or_default().push(m.network.id);
            }
            networks.insert(
                m.network.id,
                NetworkEntry {
                    membership: m.clone(),
                    tun: None,
                },
            );
        }

        let inner = Arc::new(Inner {
            keypair: config.keypair,
            secret,
            public,
            hostname: config.hostname,
            os: config.os,
            udp,
            dual_stack,
            udp_port,
            dns: RwLock::new(DnsTable::new()),
            keepalive: config.persistent_keepalive,
            relay_only: config.relay_only,
            gateway: config.gateway,
            peers: RwLock::new(PeerTable::default()),
            networks: RwLock::new(networks),
            lighthouses: Mutex::new(HashMap::new()),
            catch_all: RwLock::new(None),
            events,
            protector,
            tasks: Mutex::new(Vec::new()),
            exposes: Mutex::new(Vec::new()),
            pending_joins: Mutex::new(HashMap::new()),
            me: Mutex::new(std::sync::Weak::new()),
        });
        *inner.me.lock() = Arc::downgrade(&inner);

        let udp_task = tokio::spawn(udp_loop(inner.clone()));
        let timer_task = tokio::spawn(timer_loop(inner.clone()));
        inner.tasks.lock().extend([udp_task, timer_task]);

        for lh in by_lighthouse.into_keys() {
            inner.ensure_lighthouse(lh);
        }
        inner.rebuild_dns();
        tracing::info!(node = %inner.keypair.public, udp_port, dual_stack, "engine started");
        Ok((Engine { inner }, events_rx))
    }

    pub fn node_id(&self) -> NodeId {
        self.inner.keypair.public
    }

    pub fn udp_port(&self) -> u16 {
        self.inner.udp_port
    }

    /// Raw UDP socket handle, for platforms that need it (Android protect()).
    pub fn udp_raw(&self) -> i64 {
        raw_socket(&self.inner.udp)
    }

    pub fn memberships(&self) -> Vec<Membership> {
        self.inner.memberships()
    }

    /// Join a network with an invite. Resolves once the lighthouse has accepted.
    pub async fn join(&self, invite: &Invite) -> Result<NetworkInfo, EngineError> {
        let all = LighthouseAddr::all_from_invite(invite);
        if let Some(existing) = self.inner.networks.read().get(&invite.network) {
            return Ok(existing.membership.network.clone());
        }
        self.inner
            .pending_joins
            .lock()
            .insert(invite.network, all.clone());
        let mut handles = Vec::new();
        for lh in &all {
            handles.push(self.inner.ensure_lighthouse(lh.clone()));
        }
        // Join through the first lighthouse that answers; a replica proxies the
        // request to the primary. Give the connections a moment to come up.
        let mut handle = handles[0].clone();
        for _ in 0..30 {
            if let Some(h) = handles.iter().find(|h| h.is_connected()) {
                handle = h.clone();
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        handle
            .cmd
            .send(ControlCmd::Join {
                network: invite.network,
                token: invite.token,
                reply: tx,
            })
            .await
            .map_err(|_| EngineError::Stopped)?;
        let result = match tokio::time::timeout(JOIN_TIMEOUT, rx).await {
            Ok(Ok(Ok(info))) => Ok(info),
            Ok(Ok(Err(reason))) => Err(EngineError::JoinRejected(reason)),
            Ok(Err(_)) => Err(EngineError::Stopped),
            Err(_) => {
                let detail = handle
                    .last_error
                    .lock()
                    .clone()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default();
                Err(EngineError::JoinTimeout(detail))
            }
        };
        self.inner.pending_joins.lock().remove(&invite.network);
        if result.is_err() {
            // Drop lighthouses we only connected to for this join.
            for lh in &all {
                if !self.inner.has_memberships_with(lh) {
                    self.inner.drop_lighthouse(lh);
                }
            }
        }
        result
    }

    /// Leave a network. Works even if the lighthouse is unreachable; the
    /// lighthouse side is cleaned up when it next hears from us or by an admin.
    pub async fn leave(&self, network: NetworkId) -> Result<(), EngineError> {
        let all = self
            .inner
            .networks
            .read()
            .get(&network)
            .map(|e| e.membership.lighthouses())
            .ok_or(EngineError::UnknownNetwork(network))?;
        // Tell the first lighthouse that answers; replicas proxy to the primary.
        for lh in &all {
            let handle = self.inner.lighthouses.lock().get(lh).cloned();
            let Some(h) = handle else { continue };
            if !h.is_connected() {
                continue;
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            if h.cmd
                .send(ControlCmd::Leave { network, reply: tx })
                .await
                .is_ok()
                && tokio::time::timeout(LEAVE_TIMEOUT, rx).await.is_ok()
            {
                break;
            }
        }
        self.inner.membership_removed(&all[0], network);
        for lh in &all {
            if !self.inner.has_memberships_with(lh) {
                self.inner.drop_lighthouse(lh);
            }
        }
        Ok(())
    }

    /// Attach a TUN device. Packets read from it enter the overlay; packets for
    /// its scope are written to it.
    pub fn attach_tun(&self, scope: TunScope, dev: Arc<dyn TunDevice>) -> Result<(), EngineError> {
        let task = tokio::spawn(tun_loop(self.inner.clone(), dev.clone()));
        let att = TunAttachment { dev, task };
        match scope {
            TunScope::Network(id) => {
                let mut nets = self.inner.networks.write();
                let entry = nets.get_mut(&id).ok_or(EngineError::UnknownNetwork(id))?;
                entry.tun = Some(att);
            }
            TunScope::All => {
                *self.inner.catch_all.write() = Some(att);
            }
        }
        Ok(())
    }

    pub fn detach_tun(&self, scope: TunScope) {
        match scope {
            TunScope::Network(id) => {
                if let Some(e) = self.inner.networks.write().get_mut(&id) {
                    e.tun = None;
                }
            }
            TunScope::All => {
                *self.inner.catch_all.write() = None;
            }
        }
    }

    /// Ask the network's lighthouse for an ephemeral public port forwarding to
    /// `target` (`host:port` as reachable from this node).
    pub async fn expose(
        &self,
        network: NetworkId,
        proto: ig_proto::tunnel::ForwardProto,
        public_port: Option<u16>,
        target: String,
        label: String,
        lighthouse: Option<String>,
    ) -> Result<ig_proto::tunnel::ForwardInfo, EngineError> {
        let (all, names) = {
            let nets = self.inner.networks.read();
            let e = nets
                .get(&network)
                .ok_or(EngineError::UnknownNetwork(network))?;
            let names: HashMap<LighthouseAddr, String> = e
                .membership
                .network
                .lighthouses
                .iter()
                .map(|r| (LighthouseAddr::from_ref(r), r.name.clone()))
                .collect();
            (e.membership.lighthouses(), names)
        };
        let handle = {
            let handles = self.inner.lighthouses.lock();
            let chosen = match &lighthouse {
                Some(want) => all
                    .iter()
                    .find(|lh| {
                        lh.host == *want
                            || lh.host_port() == *want
                            || names.get(lh).is_some_and(|n| n == want)
                            || lh.key.to_string() == *want
                    })
                    .cloned()
                    .ok_or_else(|| {
                        EngineError::Refused(format!("no lighthouse `{want}` in this network"))
                    })?,
                None => all
                    .iter()
                    .find(|lh| handles.get(lh).is_some_and(|h| h.is_connected()))
                    .cloned()
                    .ok_or_else(|| EngineError::Refused("no lighthouse is connected".into()))?,
            };
            handles.get(&chosen).cloned().ok_or(EngineError::Stopped)?
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        handle
            .cmd
            .send(ControlCmd::Expose {
                network,
                proto,
                public_port,
                target,
                label,
                reply: tx,
            })
            .await
            .map_err(|_| EngineError::Stopped)?;
        match tokio::time::timeout(Duration::from_secs(15), rx).await {
            Ok(Ok(Ok(info))) => Ok(info),
            Ok(Ok(Err(reason))) => Err(EngineError::Refused(reason)),
            Ok(Err(_)) => Err(EngineError::Stopped),
            Err(_) => Err(EngineError::NoReply),
        }
    }

    /// Give an ephemeral forward back.
    pub async fn unexpose(&self, id: &str) -> Result<(), EngineError> {
        let lh = self
            .inner
            .exposes
            .lock()
            .iter()
            .find(|(_, r)| r.id == id)
            .map(|(lh, _)| lh.clone());
        let Some(lh) = lh else {
            return Err(EngineError::Refused(format!(
                "no ephemeral forward with id {id}"
            )));
        };
        let handle = self
            .inner
            .lighthouses
            .lock()
            .get(&lh)
            .cloned()
            .ok_or(EngineError::Stopped)?;
        handle
            .cmd
            .send(ControlCmd::Unexpose { id: id.to_string() })
            .await
            .map_err(|_| EngineError::Stopped)
    }

    /// Open a control session with a lighthouse without joining anything. The
    /// lighthouse's own embedded engine uses this: its memberships arrive with
    /// the `Resume` reply.
    pub fn connect_lighthouse(&self, addr: LighthouseAddr) {
        self.inner.ensure_lighthouse(addr);
    }

    /// Tell every lighthouse our local addresses may have changed.
    pub fn refresh_endpoints(&self) {
        for h in self.inner.lighthouses.lock().values() {
            let _ = h.cmd.try_send(ControlCmd::RefreshEndpoints);
        }
    }

    pub fn status(&self) -> StatusReport {
        self.inner.status()
    }

    pub async fn shutdown(&self) {
        let handles: Vec<_> = self
            .inner
            .lighthouses
            .lock()
            .drain()
            .map(|(_, h)| h)
            .collect();
        for h in handles {
            let _ = h.cmd.send(ControlCmd::Shutdown).await;
            let task = h.task.lock().take();
            if let Some(t) = task {
                let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
            }
        }
        for t in self.inner.tasks.lock().drain(..) {
            t.abort();
        }
        self.inner
            .networks
            .write()
            .values_mut()
            .for_each(|e| e.tun = None);
        *self.inner.catch_all.write() = None;
    }
}

fn protect(p: &dyn SocketProtector, udp: &UdpSocket) {
    p.protect(raw_socket(udp));
}

#[cfg(unix)]
fn raw_socket(s: &UdpSocket) -> i64 {
    use std::os::fd::AsRawFd;
    s.as_raw_fd() as i64
}

#[cfg(windows)]
fn raw_socket(s: &UdpSocket) -> i64 {
    use std::os::windows::io::AsRawSocket;
    s.as_raw_socket() as i64
}

impl Inner {
    pub fn emit(&self, ev: EngineEvent) {
        if let Err(e) = self.events.try_send(ev) {
            tracing::warn!("event channel full or closed, dropping {:?}", e);
        }
    }

    pub fn protect_tcp(&self, tcp: &tokio::net::TcpStream) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            self.protector.protect(tcp.as_raw_fd() as i64);
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            self.protector.protect(tcp.as_raw_socket() as i64);
        }
    }

    pub fn udp_send(&self, data: &[u8], to: SocketAddr) {
        if !reachable(to, self.dual_stack) {
            return;
        }
        if let Err(e) = self.udp.try_send_to(data, to_wire(to, self.dual_stack)) {
            tracing::trace!(%to, error = %e, "udp send failed");
        }
    }

    fn ensure_lighthouse(self: &Arc<Self>, addr: LighthouseAddr) -> Arc<LighthouseHandle> {
        let mut map = self.lighthouses.lock();
        if let Some(h) = map.get(&addr) {
            return h.clone();
        }
        // One lighthouse reachable under two names is still one lighthouse:
        // keep a single session per key.
        if let Some(h) = map.values().find(|h| h.addr.key == addr.key).cloned() {
            return h;
        }
        let h = control::spawn(self.clone(), addr.clone());
        map.insert(addr, h.clone());
        h
    }

    /// `ensure_lighthouse` for callers that only hold `&self`.
    fn ensure_lighthouse_arc(&self, addr: LighthouseAddr) {
        let me = self.me.lock().upgrade();
        if let Some(me) = me {
            me.ensure_lighthouse(addr);
        }
    }

    fn drop_lighthouse(&self, addr: &LighthouseAddr) {
        if let Some(h) = self.lighthouses.lock().remove(addr) {
            let _ = h.cmd.try_send(ControlCmd::Shutdown);
        }
    }

    pub fn memberships(&self) -> Vec<Membership> {
        let mut v: Vec<Membership> = self
            .networks
            .read()
            .values()
            .map(|e| e.membership.clone())
            .collect();
        v.sort_by(|a, b| a.network.name.cmp(&b.network.name));
        v
    }

    pub fn remembered_exposes(&self, lh: &LighthouseAddr) -> Vec<ExposeRequest> {
        self.exposes
            .lock()
            .iter()
            .filter(|(l, _)| l == lh)
            .map(|(_, r)| r.clone())
            .collect()
    }

    pub fn remember_expose(&self, lh: &LighthouseAddr, f: &ig_proto::tunnel::ForwardInfo) {
        let mut v = self.exposes.lock();
        v.retain(|(_, r)| {
            r.id != f.id && !(r.target == f.target && r.network == f.network && r.proto == f.proto)
        });
        v.push((
            lh.clone(),
            ExposeRequest {
                id: f.id.clone(),
                network: f.network,
                proto: f.proto,
                public_port: f.public_port,
                target: f.target.clone(),
                label: f.label.clone(),
            },
        ));
    }

    pub fn forget_expose(&self, id: &str) {
        self.exposes.lock().retain(|(_, r)| r.id != id);
    }

    pub fn has_memberships_with(&self, lh: &LighthouseAddr) -> bool {
        self.networks
            .read()
            .values()
            .any(|e| e.membership.has_lighthouse(lh))
            || self.pending_joins.lock().values().any(|v| v.contains(lh))
    }

    fn overlay_cidrs(&self) -> (Vec<Ipv4Net>, Vec<Ipv6Net>) {
        let nets = self.networks.read();
        (
            nets.values().map(|e| e.membership.network.cidr).collect(),
            nets.values()
                .filter_map(|e| e.membership.network.cidr6)
                .collect(),
        )
    }

    pub fn local_candidates(&self) -> Vec<SocketAddr> {
        let (v4, v6) = self.overlay_cidrs();
        crate::endpoints::local_candidates(self.udp_port, &v4, &v6, self.dual_stack)
    }

    /// LAN prefixes reported to the lighthouse when we offer to be a gateway.
    pub fn local_subnets(&self) -> Vec<Ipv4Net> {
        if !self.gateway {
            return Vec::new();
        }
        let (v4, _) = self.overlay_cidrs();
        crate::endpoints::local_subnets(&v4)
    }

    pub fn local_subnets6(&self) -> Vec<Ipv6Net> {
        if !self.gateway {
            return Vec::new();
        }
        let (_, v6) = self.overlay_cidrs();
        crate::endpoints::local_subnets6(&v6)
    }

    /// Device we gateway whose overlay address is `dst`: (network, physical address).
    fn my_device_for(&self, dst: &IpAddr) -> Option<(NetworkId, IpAddr)> {
        let me = self.keypair.public;
        let nets = self.networks.read();
        for e in nets.values() {
            for d in e.membership.network.my_devices(&me) {
                if let Some(t) = d.target_for(dst) {
                    return Some((e.membership.network.id, t));
                }
            }
        }
        None
    }

    /// Device we gateway whose physical address is `src`, for a reply going to
    /// `dst`: (network, overlay address). The network is the one `dst` belongs
    /// to, so the same physical address may be a device in several networks.
    fn my_device_by_target(&self, src: &IpAddr, dst: &IpAddr) -> Option<(NetworkId, IpAddr)> {
        let me = self.keypair.public;
        let net_of_dst = {
            let nets = self.networks.read();
            nets.values()
                .find(|e| e.membership.network.addresses().contains(dst))
                .map(|e| e.membership.network.id)
                .or_else(|| {
                    let t = self.peers.read();
                    let id = t.by_addr.get(dst)?;
                    t.by_id.get(id).and_then(|p| p.lock().network_of(dst))
                })
        };
        let nets = self.networks.read();
        let candidates: Vec<&NetworkEntry> = match net_of_dst {
            Some(n) => nets.get(&n).into_iter().collect(),
            None => nets.values().collect(),
        };
        for e in candidates {
            for d in e.membership.network.my_devices(&me) {
                if let Some(o) = d.overlay_for(src) {
                    return Some((e.membership.network.id, o));
                }
            }
        }
        None
    }

    /// Rebuild the DNS table from memberships and peers.
    fn rebuild_dns(&self) {
        let mut table = DnsTable::new();
        let nets: Vec<NetworkInfo> = self
            .networks
            .read()
            .values()
            .map(|e| e.membership.network.clone())
            .collect();
        for n in &nets {
            table.add_zone(&n.dns_domain);
            if !n.dns_name.is_empty() {
                table.add(
                    &n.dns_name,
                    &ig_proto::control::dns_label(&n.name),
                    &n.dns_domain,
                    &n.addresses(),
                );
            }
            for d in &n.devices {
                table.add(
                    &d.dns_name,
                    &ig_proto::control::dns_label(&n.name),
                    &n.dns_domain,
                    &d.addresses(),
                );
            }
        }
        {
            let t = self.peers.read();
            for p in t.by_id.values() {
                let p = p.lock();
                for (net_id, label) in &p.dns_names {
                    let Some(n) = nets.iter().find(|n| n.id == *net_id) else {
                        continue;
                    };
                    let Some(addrs) = p.addresses.get(net_id) else {
                        continue;
                    };
                    table.add(
                        label,
                        &ig_proto::control::dns_label(&n.name),
                        &n.dns_domain,
                        addrs,
                    );
                }
            }
        }
        *self.dns.write() = table;
    }

    /// Is `dst` the DNS responder address of one of our networks?
    fn is_dns_server(&self, dst: &IpAddr) -> bool {
        self.networks.read().values().any(|e| {
            let n = &e.membership.network;
            match dst {
                IpAddr::V4(v4) => n.dns_server_v4() == *v4,
                IpAddr::V6(v6) => n.dns_server_v6() == Some(*v6),
            }
        })
    }

    fn is_lighthouse_udp(&self, addr: SocketAddr) -> Option<Arc<LighthouseHandle>> {
        self.lighthouses
            .lock()
            .values()
            .find(|h| *h.relay.udp_addr.read() == Some(addr))
            .cloned()
    }

    // ---- membership changes (called from control tasks) -------------------

    pub fn membership_added(&self, lh: &LighthouseAddr, info: NetworkInfo) {
        let extra: Vec<LighthouseAddr> = {
            let pending = self
                .pending_joins
                .lock()
                .get(&info.id)
                .cloned()
                .unwrap_or_default();
            let mut v: Vec<LighthouseAddr> = pending.into_iter().filter(|l| l != lh).collect();
            for r in &info.lighthouses {
                let a = LighthouseAddr::from_ref(r);
                if a != *lh && !v.contains(&a) {
                    v.push(a);
                }
            }
            v
        };
        for l in &extra {
            self.ensure_lighthouse_arc(l.clone());
        }
        {
            let mut nets = self.networks.write();
            for other in nets.values() {
                let c = other.membership.network.cidr;
                if other.membership.network.id != info.id
                    && (c.contains(&info.cidr) || info.cidr.contains(&c))
                {
                    tracing::warn!(
                        new = %info.name, existing = %other.membership.network.name,
                        "network CIDRs overlap; routing between them is ambiguous"
                    );
                }
            }
            nets.insert(
                info.id,
                NetworkEntry {
                    membership: Membership {
                        lighthouse: lh.clone(),
                        extra_lighthouses: extra.clone(),
                        network: info.clone(),
                    },
                    tun: None,
                },
            );
        }
        self.rebuild_dns();
        tracing::info!(network = %info.name, address = %info.address, "joined network");
        self.emit(EngineEvent::MembershipsChanged(self.memberships()));
    }

    pub fn membership_removed(&self, _lh: &LighthouseAddr, id: NetworkId) {
        let removed = self.networks.write().remove(&id);
        if removed.is_none() {
            return;
        }
        {
            let mut t = self.peers.write();
            let mut gone = Vec::new();
            for (pid, p) in t.by_id.iter() {
                let mut p = p.lock();
                p.addresses.remove(&id);
                p.dns_names.remove(&id);
                if p.addresses.is_empty() {
                    gone.push((*pid, p.index));
                }
            }
            for (pid, idx) in gone {
                t.by_id.remove(&pid);
                t.by_index.remove(&idx);
            }
            t.rebuild_routes();
        }
        self.rebuild_dns();
        tracing::info!(network = %id, "left network");
        self.emit(EngineEvent::MembershipsChanged(self.memberships()));
        self.emit(EngineEvent::PeersChanged);
    }

    /// Full state of one network as pushed by its lighthouse.
    pub fn network_state(
        &self,
        h: &Arc<LighthouseHandle>,
        info: NetworkInfo,
        peers: Vec<PeerInfo>,
    ) {
        let mut membership_changed = false;
        {
            let mut nets = self.networks.write();
            match nets.get_mut(&info.id) {
                Some(entry) => {
                    if entry.membership.network != info {
                        entry.membership.network = info.clone();
                        entry.membership.sync_lighthouses_from_info();
                        for l in entry.membership.lighthouses() {
                            self.ensure_lighthouse_arc(l);
                        }
                        membership_changed = true;
                    }
                }
                None => {
                    // Resume told us about a network we did not have locally.
                    nets.insert(
                        info.id,
                        NetworkEntry {
                            membership: Membership {
                                lighthouse: h.addr.clone(),
                                extra_lighthouses: info
                                    .lighthouses
                                    .iter()
                                    .map(LighthouseAddr::from_ref)
                                    .filter(|l| *l != h.addr)
                                    .collect(),
                                network: info.clone(),
                            },
                            tun: None,
                        },
                    );
                    membership_changed = true;
                }
            }
        }
        if membership_changed {
            self.emit(EngineEvent::MembershipsChanged(self.memberships()));
        }

        let me = self.keypair.public;
        let mut renegotiate: Vec<Arc<Mutex<Peer>>> = Vec::new();
        let mut t = self.peers.write();
        let mut present: HashSet<NodeId> = HashSet::new();
        for pi in peers {
            if pi.node == me {
                continue;
            }
            present.insert(pi.node);
            let arc = match t.by_id.get(&pi.node) {
                Some(a) => a.clone(),
                None => {
                    let index = t.next_index;
                    t.next_index = (t.next_index + 1) & 0x00ff_ffff;
                    let tunn = Tunn::new(
                        self.secret.clone(),
                        PublicKey::from(pi.node.0),
                        None,
                        self.keepalive,
                        index,
                        None,
                    );
                    let peer = Peer {
                        id: pi.node,
                        index,
                        hostname: pi.hostname.clone(),
                        online: pi.online,
                        tunn,
                        addresses: HashMap::new(),
                        dns_names: HashMap::new(),
                        candidates: Vec::new(),
                        direct: None,
                        last_direct_rx: None,
                        last_relay_rx: None,
                        last_tx: None,
                        last_punch: None,
                        relay: None,
                        relay_network: None,
                        tx_bytes: 0,
                        rx_bytes: 0,
                        filter: PeerFilter::new(),
                    };
                    let arc = Arc::new(Mutex::new(peer));
                    t.by_id.insert(pi.node, arc.clone());
                    t.by_index.insert(index, pi.node);
                    arc
                }
            };
            let mut p = arc.lock();
            p.hostname = pi.hostname.clone();
            p.online = pi.online;
            let mut addrs = pi.addresses();
            for d in info.devices_via(&pi.node) {
                addrs.extend(d.addresses());
            }
            p.addresses.insert(info.id, addrs);
            p.dns_names.insert(info.id, pi.dns_name.clone());
            let primary = match &p.relay {
                Some(r) => r.addr == h.addr,
                None => {
                    p.relay = Some(h.relay.clone());
                    p.relay_network = Some(info.id);
                    true
                }
            };
            if primary {
                // A peer that restarted shows up with new endpoints. Our confirmed
                // direct endpoint and WireGuard session are then stale: drop the
                // path and start a fresh handshake towards the new candidates so
                // traffic resumes in milliseconds rather than after the WireGuard
                // retry timers (15 s or more).
                let stale_direct = p.direct.is_some_and(|d| !pi.endpoints.contains(&d));
                let changed = {
                    let mut old = p.candidates.clone();
                    let mut new = pi.endpoints.clone();
                    old.sort();
                    new.sort();
                    old != new
                };
                p.set_candidates(&pi.endpoints);
                if changed && stale_direct {
                    tracing::info!(peer = %p.hostname, "peer endpoints changed; renegotiating");
                    p.direct = None;
                    renegotiate.push(arc.clone());
                }
            } else {
                p.merge_candidates(&pi.endpoints);
            }
        }
        // Peers that left this network.
        let mut gone = Vec::new();
        for (pid, p) in t.by_id.iter() {
            if present.contains(pid) {
                continue;
            }
            let mut p = p.lock();
            p.dns_names.remove(&info.id);
            if p.addresses.remove(&info.id).is_some() && p.addresses.is_empty() {
                gone.push((*pid, p.index));
            }
        }
        for (pid, idx) in gone {
            t.by_id.remove(&pid);
            t.by_index.remove(&idx);
        }
        t.rebuild_routes();
        drop(t);
        let mut out = vec![0u8; OUT_BUF];
        for arc in renegotiate {
            let mut p = arc.lock();
            if let TunnResult::WriteToNetwork(b) =
                p.tunn.format_handshake_initiation(&mut out, true)
            {
                let b = b.to_vec();
                p.last_punch = None;
                self.transmit(&mut p, &b);
            }
        }
        self.rebuild_dns();
        self.emit(EngineEvent::PeersChanged);
    }

    pub fn mark_lighthouse_peers_offline(&self, lh: &LighthouseAddr) {
        let t = self.peers.read();
        for p in t.by_id.values() {
            let mut p = p.lock();
            if p.relay.as_ref().is_some_and(|r| r.addr == *lh) {
                p.online = false;
            }
        }
    }

    /// A peer asked (through the lighthouse) that we send towards it now.
    pub fn punch_towards(&self, from: &NodeId, endpoints: &[SocketAddr]) {
        if self.relay_only {
            return;
        }
        let Some(arc) = self.peers.read().by_id.get(from).cloned() else {
            return;
        };
        let mut p = arc.lock();
        p.merge_candidates(endpoints);
        let mut out = vec![0u8; OUT_BUF];
        // A keepalive opens our NAT towards every candidate. With no session
        // yet, this becomes a handshake initiation instead, which is also fine.
        if let TunnResult::WriteToNetwork(b) = p.tunn.encapsulate(&[], &mut out) {
            for c in p.candidates.clone() {
                self.udp_send(b, c);
            }
            if let Some(d) = p.direct {
                self.udp_send(b, d);
            }
        }
        p.last_punch = Some(Instant::now());
    }

    // ---- data plane -----------------------------------------------------------

    /// Send an already-encrypted packet to a peer over the best path we have.
    fn transmit(&self, p: &mut Peer, b: &[u8]) {
        let now = Instant::now();
        p.last_tx = Some(now);
        if let Some(d) = p.direct {
            self.udp_send(b, d);
            return;
        }
        let relay_addr = p.relay.as_ref().and_then(|r| *r.udp_addr.read());
        if let (Some(r), Some(net)) = (relay_addr, p.relay_network) {
            self.udp_send(&disco::encode_relay(&net, &p.id, b), r);
        }
        if self.relay_only {
            return;
        }
        if p.may_punch(now) || relay_addr.is_none() {
            for c in &p.candidates {
                self.udp_send(b, *c);
            }
            if let (Some(rp), Some(net)) = (&p.relay, p.relay_network) {
                let _ = rp.cmd.try_send(ControlCmd::Punch {
                    network: net,
                    target: p.id,
                });
            }
        }
    }

    /// Reply along the path a packet arrived on.
    fn reply(&self, p: &mut Peer, b: &[u8], from: SocketAddr, via_relay: bool) {
        p.last_tx = Some(Instant::now());
        if via_relay {
            if let Some(net) = p.relay_network {
                self.udp_send(&disco::encode_relay(&net, &p.id, b), from);
            }
        } else {
            self.udp_send(b, from);
        }
    }

    fn handle_tun_packet(&self, pkt: &[u8], out: &mut [u8], dev: &Arc<dyn TunDevice>) {
        let Some(dst) = packet::dst(pkt) else {
            return;
        };
        let Some(src) = packet::src(pkt) else {
            return;
        };
        // Gateway: a reply from a device we front comes back from the kernel
        // with the physical source; put the overlay address on it first.
        let mut owned: Vec<u8>;
        let mut pkt = pkt;
        let mut src = src;
        if let Some((_, overlay)) = self.my_device_by_target(&src, &dst) {
            owned = pkt.to_vec();
            if !crate::nat::rewrite_src(&mut owned, overlay) {
                return;
            }
            pkt = &owned;
            src = overlay;
            // Reply to ourselves (we talked to our own device): hairpin.
            if self.is_my_address(&dst) {
                let _ = dev.send(pkt);
                return;
            }
        }
        // Gateway: traffic from this host to a device we front ourselves.
        if let Some((net, target)) = self.my_device_for(&dst) {
            let policy_ok = {
                let nets = self.networks.read();
                nets.get(&net)
                    .is_some_and(|e| e.membership.network.addresses().contains(&src))
            };
            if !policy_ok {
                return;
            }
            let mut translated = pkt.to_vec();
            if crate::nat::rewrite_dst(&mut translated, target) {
                let _ = dev.send(&translated);
            }
            return;
        }
        if self.is_dns_server(&dst) {
            let reply = crate::dns::reply_packet(&self.dns.read(), pkt);
            if let Some(reply) = reply {
                if let Err(e) = dev.send(&reply) {
                    tracing::trace!(error = %e, "dns reply write failed");
                }
            }
            return;
        }
        let arc = {
            let t = self.peers.read();
            match t.by_addr.get(&dst).and_then(|id| t.by_id.get(id)) {
                Some(a) => a.clone(),
                None => {
                    tracing::trace!(%dst, "no peer for destination");
                    return;
                }
            }
        };
        let mut p = arc.lock();
        let Some(net) = p.network_of(&dst) else {
            return;
        };
        let src_ok = {
            let nets = self.networks.read();
            nets.get(&net).is_some_and(|e| {
                let n = &e.membership.network;
                n.addresses().contains(&src)
                    || n.my_devices(&self.keypair.public)
                        .iter()
                        .any(|d| d.addresses().contains(&src))
            })
        };
        if !src_ok {
            tracing::trace!(%src, %dst, "source address does not belong to the destination's network");
            return;
        }
        p.filter.note_outbound(pkt);
        p.tx_bytes += pkt.len() as u64;
        match p.tunn.encapsulate(pkt, out) {
            TunnResult::WriteToNetwork(b) => {
                let b = b.to_vec();
                self.transmit(&mut p, &b);
            }
            TunnResult::Err(e) => tracing::debug!(peer = %p.id.short(), ?e, "encapsulate failed"),
            _ => {}
        }
    }

    fn handle_datagram(&self, data: &[u8], from: SocketAddr, out: &mut [u8]) {
        if disco::is_disco(data) {
            match disco::decode(data) {
                Some(disco::Disco::ProbeReply { observed, .. }) => {
                    if let Some(h) = self.is_lighthouse_udp(from) {
                        let ok = h
                            .session_token
                            .read()
                            .is_some_and(|t| disco::verify_mac(data, &t));
                        if ok {
                            let changed = *h.reflexive.read() != Some(observed);
                            *h.reflexive.write() = Some(observed);
                            if changed {
                                tracing::info!(lighthouse = %h.addr, %observed, "public endpoint");
                            }
                        }
                    }
                }
                Some(disco::Disco::Relayed { payload, .. })
                    if self.is_lighthouse_udp(from).is_some() =>
                {
                    self.handle_wireguard(payload, from, true, out);
                }
                _ => {}
            }
            return;
        }
        self.handle_wireguard(data, from, false, out);
    }

    fn handle_wireguard(&self, data: &[u8], from: SocketAddr, via_relay: bool, out: &mut [u8]) {
        let Ok(parsed) = Tunn::parse_incoming_packet(data) else {
            return;
        };
        let mut is_cookie = false;
        let peer_id = match &parsed {
            Packet::HandshakeInit(p) => match parse_handshake_anon(&self.secret, &self.public, p) {
                Ok(half) => NodeId(half.peer_static_public),
                Err(e) => {
                    tracing::trace!(%from, ?e, "handshake from unknown key");
                    return;
                }
            },
            Packet::HandshakeResponse(p) => {
                match self.peers.read().by_index.get(&(p.receiver_idx >> 8)) {
                    Some(id) => *id,
                    None => return,
                }
            }
            Packet::PacketCookieReply(p) => {
                is_cookie = true;
                match self.peers.read().by_index.get(&(p.receiver_idx >> 8)) {
                    Some(id) => *id,
                    None => return,
                }
            }
            Packet::PacketData(p) => match self.peers.read().by_index.get(&(p.receiver_idx >> 8)) {
                Some(id) => *id,
                None => return,
            },
        };
        let Some(arc) = self.peers.read().by_id.get(&peer_id).cloned() else {
            tracing::trace!(peer = %peer_id.short(), "packet from node that is not our peer");
            return;
        };
        let mut p = arc.lock();
        let src_ip = if via_relay { None } else { Some(from.ip()) };
        let now = Instant::now();
        let mut authenticated = true;
        match p.tunn.decapsulate(src_ip, data, out) {
            TunnResult::WriteToNetwork(b) => {
                let b = b.to_vec();
                if !via_relay && !is_cookie && !self.relay_only {
                    p.direct = Some(from);
                    p.last_direct_rx = Some(now);
                }
                self.reply(&mut p, &b, from, via_relay);
                // Flush packets queued while the handshake was in flight.
                while let TunnResult::WriteToNetwork(b) = p.tunn.decapsulate(None, &[], out) {
                    let b = b.to_vec();
                    self.reply(&mut p, &b, from, via_relay);
                }
            }
            TunnResult::WriteToTunnelV4(b, src) => {
                let len = b.len();
                if self.deliver(&mut p, IpAddr::V4(src), &out[..len]) {
                    p.rx_bytes += len as u64;
                }
            }
            TunnResult::WriteToTunnelV6(b, src) => {
                let len = b.len();
                if self.deliver(&mut p, IpAddr::V6(src), &out[..len]) {
                    p.rx_bytes += len as u64;
                }
            }
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                authenticated = false;
                tracing::trace!(peer = %p.id.short(), %from, ?e, "decapsulate failed");
            }
        }
        if authenticated && !is_cookie {
            if via_relay || self.relay_only {
                p.last_relay_rx = Some(now);
            } else {
                if p.direct != Some(from) {
                    tracing::info!(peer = %p.hostname, endpoint = %from, "direct path established");
                }
                p.direct = Some(from);
                p.last_direct_rx = Some(now);
            }
        }
    }

    /// Validate a decrypted packet and hand it to the right TUN.
    fn deliver(&self, p: &mut Peer, src: IpAddr, pkt: &[u8]) -> bool {
        let Some(net) = p.network_of(&src) else {
            tracing::trace!(peer = %p.id.short(), %src, "source not in peer's allowed addresses");
            return false;
        };
        let Some(dst) = packet::dst(pkt) else {
            return false;
        };
        let nets = self.networks.read();
        let Some(entry) = nets.get(&net) else {
            return false;
        };
        let device = entry
            .membership
            .network
            .my_devices(&self.keypair.public)
            .into_iter()
            .find_map(|d| d.target_for(&dst));
        if device.is_none() && !entry.membership.network.addresses().contains(&dst) {
            tracing::trace!(%dst, network = %entry.membership.network.name, "packet not addressed to us in this network");
            return false;
        }
        if !p
            .filter
            .allow_inbound(&entry.membership.network.policy, pkt)
        {
            tracing::debug!(peer = %p.hostname, network = %entry.membership.network.name, "dropped by policy");
            return false;
        }
        let dev = match &entry.tun {
            Some(t) => t.dev.clone(),
            None => match &*self.catch_all.read() {
                Some(t) => t.dev.clone(),
                None => return false,
            },
        };
        drop(nets);
        if let Some(target) = device {
            // Gateway: hand the packet to the kernel addressed to the physical
            // device; the kernel masquerades it onto the LAN.
            let mut translated = pkt.to_vec();
            if !crate::nat::rewrite_dst(&mut translated, target) {
                return false;
            }
            if let Err(e) = dev.send(&translated) {
                tracing::trace!(error = %e, "tun write failed");
                return false;
            }
            return true;
        }
        if let Err(e) = dev.send(pkt) {
            tracing::trace!(error = %e, "tun write failed");
            return false;
        }
        true
    }

    fn is_my_address(&self, addr: &IpAddr) -> bool {
        self.networks
            .read()
            .values()
            .any(|e| e.membership.network.addresses().contains(addr))
    }

    fn tick(&self, out: &mut [u8]) {
        let peers: Vec<Arc<Mutex<Peer>>> = self.peers.read().by_id.values().cloned().collect();
        let now = Instant::now();
        for arc in peers {
            let mut p = arc.lock();
            match p.tunn.update_timers(out) {
                TunnResult::WriteToNetwork(b) => {
                    let b = b.to_vec();
                    self.transmit(&mut p, &b);
                }
                TunnResult::Err(WireGuardError::ConnectionExpired) if p.direct.take().is_some() => {
                    tracing::debug!(peer = %p.hostname, "session expired, forgetting direct path");
                }
                _ => {}
            }
            if p.expire_direct(now) {
                tracing::info!(peer = %p.hostname, "direct path went quiet, falling back to relay");
            }
            // While relayed with recent traffic, keep trying for a direct path.
            let active = p
                .last_tx
                .is_some_and(|t| now.duration_since(t) < Duration::from_secs(60));
            if !self.relay_only
                && p.direct.is_none()
                && active
                && !p.candidates.is_empty()
                && p.may_punch(now)
            {
                if let TunnResult::WriteToNetwork(b) = p.tunn.encapsulate(&[], out) {
                    let b = b.to_vec();
                    for c in p.candidates.clone() {
                        self.udp_send(&b, c);
                    }
                }
                if let (Some(rp), Some(net)) = (&p.relay, p.relay_network) {
                    let _ = rp.cmd.try_send(ControlCmd::Punch {
                        network: net,
                        target: p.id,
                    });
                }
            }
        }
    }

    fn status(&self) -> StatusReport {
        let lhs: HashMap<LighthouseAddr, bool> = self
            .lighthouses
            .lock()
            .iter()
            .map(|(a, h)| (a.clone(), h.is_connected()))
            .collect();
        let networks: Vec<NetworkStatus> = {
            let nets = self.networks.read();
            let mut v: Vec<NetworkStatus> = nets
                .values()
                .map(|e| NetworkStatus {
                    info: e.membership.network.clone(),
                    lighthouse: e.membership.lighthouse.host_port(),
                    lighthouse_connected: lhs
                        .get(&e.membership.lighthouse)
                        .copied()
                        .unwrap_or(false),
                    lighthouses: e
                        .membership
                        .lighthouses()
                        .iter()
                        .map(|l| (l.host_port(), lhs.get(l).copied().unwrap_or(false)))
                        .collect(),
                    interface: e.tun.as_ref().map(|t| t.dev.name()),
                })
                .collect();
            v.sort_by(|a, b| a.info.name.cmp(&b.info.name));
            v
        };
        let nets_by_id: HashMap<NetworkId, NetworkInfo> = networks
            .iter()
            .map(|n| (n.info.id, n.info.clone()))
            .collect();
        let peers: Vec<PeerStatus> = {
            let t = self.peers.read();
            let mut v: Vec<PeerStatus> = t
                .by_id
                .values()
                .map(|p| {
                    let p = p.lock();
                    let mut addresses: Vec<(NetworkId, IpAddr)> = p
                        .addresses
                        .iter()
                        .flat_map(|(n, v)| v.iter().map(move |a| (*n, *a)))
                        .collect();
                    addresses.sort();
                    let mut names: Vec<(NetworkId, String)> = p
                        .dns_names
                        .iter()
                        .filter_map(|(n, label)| {
                            let net = nets_by_id.get(n)?;
                            Some((
                                *n,
                                format!(
                                    "{}.{}.{}",
                                    label,
                                    ig_proto::control::dns_label(&net.name),
                                    net.dns_domain
                                ),
                            ))
                        })
                        .collect();
                    names.sort();
                    PeerStatus {
                        node: p.id,
                        hostname: p.hostname.clone(),
                        online: p.online,
                        addresses,
                        names,
                        path: p.path(),
                        endpoint: p.direct,
                        last_handshake_secs_ago: p
                            .tunn
                            .time_since_last_handshake()
                            .map(|d| d.as_secs()),
                        tx_bytes: p.tx_bytes,
                        rx_bytes: p.rx_bytes,
                    }
                })
                .collect();
            v.sort_by(|a, b| a.hostname.cmp(&b.hostname));
            v
        };
        StatusReport {
            node: Some(self.keypair.public),
            hostname: self.hostname.clone(),
            udp_port: self.udp_port,
            networks,
            peers,
        }
    }
}

async fn udp_loop(inner: Arc<Inner>) {
    let mut buf = vec![0u8; MAX_PACKET];
    let mut out = vec![0u8; OUT_BUF];
    loop {
        match inner.udp.recv_from(&mut buf).await {
            Ok((n, from)) => inner.handle_datagram(&buf[..n], canonical(from), &mut out),
            Err(e) => {
                tracing::warn!(error = %e, "udp receive error");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn timer_loop(inner: Arc<Inner>) {
    let mut out = vec![0u8; OUT_BUF];
    let mut tick = tokio::time::interval(TIMER_TICK);
    loop {
        tick.tick().await;
        inner.tick(&mut out);
    }
}

async fn tun_loop(inner: Arc<Inner>, dev: Arc<dyn TunDevice>) {
    let mut buf = vec![0u8; MAX_PACKET];
    let mut out = vec![0u8; OUT_BUF];
    loop {
        match dev.recv(&mut buf).await {
            Ok(0) => continue,
            Ok(n) => inner.handle_tun_packet(&buf[..n], &mut out, &dev),
            Err(e) => {
                tracing::warn!(tun = %dev.name(), error = %e, "tun read failed, stopping reader");
                return;
            }
        }
    }
}
