//! Mobile-facing API. Kotlin (Android) talks to the engine through these types.
//!
//! The app owns the lifecycle: it creates a [`MobileEngine`] with the persisted
//! state JSON, joins networks, and when the set of networks changes it
//! re-establishes its `VpnService` interface and hands the new file descriptor to
//! [`MobileEngine::attach_tun`]. The engine protects its own sockets through the
//! [`MobileCallbacks::protect_socket`] callback so they bypass the VPN.

use ig_core::tun::TunScope;
use ig_core::{Engine, EngineConfig, EngineEvent, NodeState, SocketProtector};
use ig_proto::ipc::PeerPath;
use ig_proto::Invite;
use ig_proto::Keypair;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("{reason}")]
    Failed { reason: String },
}

impl From<anyhow::Error> for MobileError {
    fn from(e: anyhow::Error) -> Self {
        MobileError::Failed {
            reason: e.to_string(),
        }
    }
}

fn err<E: std::fmt::Display>(e: E) -> MobileError {
    MobileError::Failed {
        reason: e.to_string(),
    }
}

/// A joined network, with what `VpnService.Builder` needs.
#[derive(Clone, Debug, uniffi::Record)]
pub struct MobileNetwork {
    pub id: String,
    pub name: String,
    pub address: String,
    pub prefix_len: u8,
    pub cidr: String,
    /// IPv6 address, prefix and CIDR when the network has an IPv6 range.
    pub address6: Option<String>,
    pub prefix_len6: Option<u8>,
    pub cidr6: Option<String>,
    /// In-engine DNS responder addresses to hand to `VpnService.Builder.addDnsServer`.
    pub dns_server: String,
    pub dns_server6: Option<String>,
    /// Search domain for this network (`<network>.<domain>`) and this node's name.
    pub dns_search_domain: String,
    pub dns_name: String,
    pub lighthouse: String,
    pub lighthouse_connected: bool,
    pub policy_summary: String,
    pub relay_limit: String,
    /// False when the user turned this network off on this device.
    pub enabled: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MobilePeer {
    pub node_id: String,
    pub hostname: String,
    pub online: bool,
    /// "network=address" strings (IPv4 and IPv6).
    pub addresses: Vec<String>,
    /// Fully qualified DNS names, one per shared network.
    pub names: Vec<String>,
    /// "none", "direct" or "relay".
    pub path: String,
    pub endpoint: Option<String>,
    pub last_handshake_secs_ago: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MobileStatus {
    pub node_id: String,
    pub hostname: String,
    pub udp_port: u16,
    pub networks: Vec<MobileNetwork>,
    pub peers: Vec<MobilePeer>,
}

/// Implemented in Kotlin.
#[uniffi::export(with_foreign)]
pub trait MobileCallbacks: Send + Sync {
    /// Called for every socket the engine opens. Must call `VpnService.protect(fd)`.
    fn protect_socket(&self, fd: i32);
    /// The joined networks changed. Persist `state_json` and rebuild the VPN
    /// interface with the given networks, then call `attach_tun` with the new fd.
    fn on_networks_changed(&self, networks: Vec<MobileNetwork>, state_json: String);
    fn on_peers_changed(&self);
    fn on_lighthouse_status(&self, lighthouse: String, connected: bool);
}

struct Protector(Arc<dyn MobileCallbacks>);
impl SocketProtector for Protector {
    fn protect(&self, raw_socket: i64) {
        self.0.protect_socket(raw_socket as i32);
    }
}

#[derive(uniffi::Object)]
pub struct MobileEngine {
    rt: Runtime,
    engine: Engine,
    private_key: ig_proto::PrivateKey,
}

/// Create a fresh identity. Store the returned JSON; pass it to `MobileEngine::new`.
#[uniffi::export]
pub fn generate_state() -> String {
    serde_json::to_string(&NodeState::generate()).expect("state serializes")
}

/// Parse an invite so the UI can show what it is before joining.
#[uniffi::export]
pub fn describe_invite(invite: String) -> Result<String, MobileError> {
    let inv: Invite = invite.parse().map_err(err)?;
    Ok(format!(
        "network \"{}\" via {}:{}",
        inv.network_name, inv.host, inv.port
    ))
}

#[uniffi::export]
impl MobileEngine {
    /// Start the engine from persisted state JSON (see `generate_state`).
    #[uniffi::constructor]
    /// `connect = false` starts with the tunnel off: memberships are loaded but
    /// no lighthouse is contacted until [`MobileEngine::resume`].
    pub fn new(
        state_json: String,
        hostname: String,
        callbacks: Arc<dyn MobileCallbacks>,
        connect: bool,
    ) -> Result<Arc<Self>, MobileError> {
        init_logging();
        let state: NodeState = serde_json::from_str(&state_json).map_err(err)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("ig-engine")
            .build()
            .map_err(err)?;
        let keypair = Keypair::from_private(state.private_key.clone());
        let config = EngineConfig {
            keypair,
            hostname,
            os: "android".into(),
            udp_port: 0,
            memberships: state.memberships.clone(),
            // Mobile radios: let sessions idle instead of waking every 25 s.
            persistent_keepalive: None,
            relay_only: false,
            gateway: false,
            // The app supplies the underlying network's resolvers through
            // `set_upstream_dns` once the VPN is up.
            upstream_dns: Vec::new(),
            start_paused: !connect,
        };
        let protector = Arc::new(Protector(callbacks.clone()));
        let (engine, mut events) = rt.block_on(Engine::start(config, protector)).map_err(err)?;
        let private_key = state.private_key.clone();
        let cb = callbacks;
        let pk = private_key.clone();
        rt.spawn(async move {
            while let Some(ev) = events.recv().await {
                match ev {
                    EngineEvent::MembershipsChanged(list) => {
                        let st = NodeState {
                            private_key: pk.clone(),
                            memberships: list.clone(),
                        };
                        let json = serde_json::to_string(&st).unwrap_or_default();
                        let nets = list.iter().map(|m| to_mobile_network(m, false)).collect();
                        cb.on_networks_changed(nets, json);
                    }
                    EngineEvent::PeersChanged => cb.on_peers_changed(),
                    EngineEvent::LighthouseStatus {
                        lighthouse,
                        connected,
                    } => cb.on_lighthouse_status(lighthouse.host_port(), connected),
                }
            }
        });
        Ok(Arc::new(MobileEngine {
            rt,
            engine,
            private_key,
        }))
    }

    pub fn node_id(&self) -> String {
        self.engine.node_id().to_string()
    }

    pub fn join(&self, invite: String) -> Result<MobileNetwork, MobileError> {
        let inv: Invite = invite.parse().map_err(err)?;
        let info = self.rt.block_on(self.engine.join(&inv)).map_err(err)?;
        let lh = ig_core::LighthouseAddr::from_invite(&inv);
        Ok(to_mobile_network(
            &ig_core::Membership {
                lighthouse: lh,
                extra_lighthouses: inv
                    .extra_lighthouses
                    .iter()
                    .map(ig_core::LighthouseAddr::from_ref)
                    .collect(),
                network: info,
                enabled: true,
            },
            true,
        ))
    }

    pub fn leave(&self, network_id: String) -> Result<(), MobileError> {
        let id: ig_proto::NetworkId = network_id.parse().map_err(err)?;
        self.rt.block_on(self.engine.leave(id)).map_err(err)
    }

    /// Attach the `VpnService` TUN file descriptor. The engine takes ownership
    /// of a duplicate; the app may close its own copy.
    pub fn attach_tun(&self, fd: i32) -> Result<(), MobileError> {
        // Called from the Android main thread: enter the runtime so the engine
        // can spawn its reader task and register the fd with tokio.
        let _guard = self.rt.enter();
        let dev = tun::FdTun::from_fd(fd).map_err(err)?;
        self.engine
            .attach_tun(TunScope::All, Arc::new(dev))
            .map_err(err)
    }

    pub fn detach_tun(&self) {
        let _guard = self.rt.enter();
        self.engine.detach_tun(TunScope::All);
    }

    /// Call when connectivity changes (Wi-Fi to cellular) so lighthouses learn
    /// the new addresses quickly.
    /// Tunnel off: disconnect from every lighthouse and drop the peers.
    pub fn pause(&self) {
        let _guard = self.rt.enter();
        self.engine.pause();
    }

    /// Tunnel on: reconnect to every lighthouse of every membership.
    pub fn resume(&self) {
        let _guard = self.rt.enter();
        self.engine.resume();
    }

    pub fn network_changed(&self) {
        let _guard = self.rt.enter();
        self.engine.refresh_endpoints();
    }

    /// Resolvers for names outside the overlay. Android sends every query to
    /// the in-tunnel responder, so the engine forwards non-overlay names to
    /// these over a protected socket. Pass the underlying network's
    /// `LinkProperties.dnsServers` as "ip" or "ip:port" (port 53 by default);
    /// entries that do not parse are skipped. Call again whenever the
    /// underlying network changes. An empty list turns forwarding off.
    pub fn set_upstream_dns(&self, servers: Vec<String>) {
        let list: Vec<SocketAddr> = servers.iter().filter_map(|s| parse_upstream(s)).collect();
        self.engine.set_upstream_dns(list);
    }

    pub fn networks(&self) -> Vec<MobileNetwork> {
        let st = self.engine.status();
        st.networks
            .iter()
            .map(|n| network_record(&n.info, &n.lighthouse, n.lighthouse_connected, n.enabled))
            .collect()
    }

    /// Turn a joined network on or off on this device (the membership stays).
    pub fn set_network_enabled(
        &self,
        network_id: String,
        enabled: bool,
    ) -> Result<(), MobileError> {
        let _g = self.rt.enter();
        let id: ig_proto::NetworkId = network_id.parse().map_err(|_| MobileError::Failed {
            reason: "bad network id".into(),
        })?;
        self.engine.set_network_enabled(id, enabled).map_err(err)
    }

    pub fn status(&self) -> MobileStatus {
        let st = self.engine.status();
        let names: std::collections::HashMap<_, _> = st
            .networks
            .iter()
            .map(|n| (n.info.id, n.info.name.clone()))
            .collect();
        MobileStatus {
            node_id: st.node.map(|n| n.to_string()).unwrap_or_default(),
            hostname: st.hostname.clone(),
            udp_port: st.udp_port,
            networks: self.networks(),
            peers: st
                .peers
                .iter()
                .map(|p| MobilePeer {
                    node_id: p.node.to_string(),
                    hostname: p.hostname.clone(),
                    online: p.online,
                    addresses: p
                        .addresses
                        .iter()
                        .map(|(n, a)| {
                            format!(
                                "{}={}",
                                names.get(n).cloned().unwrap_or_else(|| n.to_string()),
                                a
                            )
                        })
                        .collect(),
                    names: p.names.iter().map(|(_, n)| n.clone()).collect(),
                    path: match p.path {
                        PeerPath::None => "none",
                        PeerPath::Direct => "direct",
                        PeerPath::Relay => "relay",
                    }
                    .into(),
                    endpoint: p.endpoint.map(|e| e.to_string()),
                    last_handshake_secs_ago: p.last_handshake_secs_ago,
                    tx_bytes: p.tx_bytes,
                    rx_bytes: p.rx_bytes,
                })
                .collect(),
        }
    }

    /// Current state JSON, for persistence.
    pub fn state_json(&self) -> String {
        let st = NodeState {
            private_key: self.private_key.clone(),
            memberships: self.engine.memberships(),
        };
        serde_json::to_string(&st).unwrap_or_default()
    }

    pub fn shutdown(&self) {
        self.rt.block_on(self.engine.shutdown());
    }
}

/// "1.1.1.1", "1.1.1.1:53", "2606:4700::1111", "[2606:4700::1111]:53" or
/// "fe80::1%wlan0" (the scope is dropped) -> socket address, port 53 by default.
fn parse_upstream(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    let s = s.split_once('%').map(|(a, _)| a).unwrap_or(s);
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa);
    }
    s.trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, 53))
}

fn policy_summary(p: &ig_proto::Policy) -> String {
    if p.is_allow_all() {
        "allow all".into()
    } else {
        p.rules
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn to_mobile_network(m: &ig_core::Membership, connected: bool) -> MobileNetwork {
    network_record(&m.network, &m.lighthouse.host_port(), connected, m.enabled)
}

fn network_record(
    n: &ig_proto::control::NetworkInfo,
    lighthouse: &str,
    connected: bool,
    enabled: bool,
) -> MobileNetwork {
    MobileNetwork {
        id: n.id.to_string(),
        name: n.name.clone(),
        address: n.address.to_string(),
        prefix_len: n.cidr.prefix_len(),
        cidr: n.cidr.to_string(),
        address6: n.address6.map(|a| a.to_string()),
        prefix_len6: n.cidr6.map(|c| c.prefix_len()),
        cidr6: n.cidr6.map(|c| c.to_string()),
        dns_server: n.dns_server_v4().to_string(),
        dns_server6: n.dns_server_v6().map(|a| a.to_string()),
        dns_search_domain: format!("{}.{}", ig_proto::control::dns_label(&n.name), n.dns_domain),
        dns_name: n.fqdn(),
        lighthouse: lighthouse.to_string(),
        lighthouse_connected: connected,
        policy_summary: policy_summary(&n.policy),
        relay_limit: n.relay_limit.to_string(),
        enabled,
    }
}

fn init_logging() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        #[cfg(target_os = "android")]
        {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Info)
                    .with_tag("intergalactic"),
            );
            let _ = tracing_log::LogTracer::init();
            let _ = tracing_subscriber::fmt()
                .with_writer(std::io::sink)
                .try_init();
            // Route tracing events into the Android log through `log`.
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(std::io::sink)
                    .finish(),
            );
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .try_init();
        }
    });
}

mod tun {
    use async_trait::async_trait;
    use ig_core::TunDevice;
    use std::io;

    /// TUN backed by a file descriptor handed over by `VpnService`.
    pub struct FdTun {
        #[cfg(unix)]
        dev: tun_rs::AsyncDevice,
        #[cfg(not(unix))]
        _fd: i32,
    }

    impl FdTun {
        pub fn from_fd(fd: i32) -> io::Result<FdTun> {
            #[cfg(unix)]
            {
                // Duplicate so the Kotlin side can close its ParcelFileDescriptor
                // without pulling the rug from under us.
                let dup = unsafe { libc_dup(fd) };
                if dup < 0 {
                    return Err(io::Error::last_os_error());
                }
                let dev = unsafe { tun_rs::AsyncDevice::from_fd(dup) }?;
                Ok(FdTun { dev })
            }
            #[cfg(not(unix))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "fd-based tun needs a unix platform",
                ))
            }
        }
    }

    #[cfg(unix)]
    unsafe fn libc_dup(fd: i32) -> i32 {
        extern "C" {
            fn dup(fd: i32) -> i32;
        }
        dup(fd)
    }

    #[async_trait]
    impl TunDevice for FdTun {
        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            #[cfg(unix)]
            {
                self.dev.recv(buf).await
            }
            #[cfg(not(unix))]
            {
                let _ = buf;
                Err(io::Error::new(io::ErrorKind::Unsupported, "no tun"))
            }
        }

        fn send(&self, pkt: &[u8]) -> io::Result<()> {
            #[cfg(unix)]
            {
                self.dev.try_send(pkt).map(|_| ())
            }
            #[cfg(not(unix))]
            {
                let _ = pkt;
                Err(io::Error::new(io::ErrorKind::Unsupported, "no tun"))
            }
        }

        fn name(&self) -> String {
            "vpn".into()
        }
    }
}
