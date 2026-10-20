//! Control-channel client: one task per lighthouse. Keeps a Noise/TCP session
//! alive, answers joins, relays membership updates to the engine, and sends UDP
//! probes so the lighthouse always knows our public address.

use crate::engine::Inner;
use crate::peer::RelayPoint;
use crate::state::LighthouseAddr;
use ig_proto::control::{ClientHello, FromLighthouse, NetworkInfo, ServerHello, ToLighthouse};
use ig_proto::noise::NoiseStream;
use ig_proto::{disco, NetworkId, NodeId, PROTOCOL_VERSION};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

const PING_EVERY: Duration = Duration::from_secs(15);
const PROBE_EVERY: Duration = Duration::from_secs(20);
const ENDPOINTS_EVERY: Duration = Duration::from_secs(30);
const JOIN_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub enum ControlCmd {
    Join {
        network: NetworkId,
        token: [u8; 16],
        reply: oneshot::Sender<Result<NetworkInfo, String>>,
    },
    Leave {
        network: NetworkId,
        reply: oneshot::Sender<()>,
    },
    Punch {
        network: NetworkId,
        target: NodeId,
    },
    /// Re-send local endpoints (called when the embedder notices an address change).
    RefreshEndpoints,
    Shutdown,
}

pub struct LighthouseHandle {
    pub addr: LighthouseAddr,
    pub relay: Arc<RelayPoint>,
    pub cmd: mpsc::Sender<ControlCmd>,
    pub connected: AtomicBool,
    pub session_token: RwLock<Option<[u8; 32]>>,
    pub reflexive: RwLock<Option<SocketAddr>>,
    pub last_error: Mutex<Option<String>>,
    pub task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl LighthouseHandle {
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

pub fn spawn(inner: Arc<Inner>, addr: LighthouseAddr) -> Arc<LighthouseHandle> {
    let (tx, rx) = mpsc::channel(64);
    let relay = Arc::new(RelayPoint {
        addr: addr.clone(),
        udp_addr: RwLock::new(None),
        cmd: tx.clone(),
    });
    let handle = Arc::new(LighthouseHandle {
        addr,
        relay,
        cmd: tx,
        connected: AtomicBool::new(false),
        session_token: RwLock::new(None),
        reflexive: RwLock::new(None),
        last_error: Mutex::new(None),
        task: Mutex::new(None),
    });
    let task = tokio::spawn(run(inner, handle.clone(), rx));
    *handle.task.lock() = Some(task);
    handle
}

async fn run(inner: Arc<Inner>, h: Arc<LighthouseHandle>, mut rx: mpsc::Receiver<ControlCmd>) {
    let mut backoff = Duration::from_secs(1);
    // Commands that arrived while we had no session. Replayed after connecting.
    let mut queued: Vec<ControlCmd> = Vec::new();
    loop {
        let session = match connect(&inner, &h).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(lighthouse = %h.addr, error = %e, "control connect failed");
                *h.last_error.lock() = Some(e.to_string());
                // Fail whatever was waiting on this attempt; callers retry.
                for cmd in queued.drain(..) {
                    match cmd {
                        ControlCmd::Join { reply, .. } => {
                            let _ = reply.send(Err(format!("lighthouse unreachable: {e}")));
                        }
                        ControlCmd::Leave { reply, .. } => {
                            let _ = reply.send(());
                        }
                        _ => {}
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    }
                    cmd = rx.recv() => match cmd {
                        None | Some(ControlCmd::Shutdown) => return,
                        Some(cmd @ ControlCmd::Join { .. }) => {
                            // A join is urgent: retry the connection right away.
                            queued.push(cmd);
                            backoff = Duration::from_secs(1);
                        }
                        Some(cmd @ ControlCmd::Leave { .. }) => queued.push(cmd),
                        Some(_) => {}
                    }
                }
                continue;
            }
        };
        backoff = Duration::from_secs(1);
        *h.last_error.lock() = None;
        h.connected.store(true, Ordering::Relaxed);
        inner.emit(crate::EngineEvent::LighthouseStatus {
            lighthouse: h.addr.clone(),
            connected: true,
        });
        tracing::info!(lighthouse = %h.addr, "control channel up");

        let outcome = session_loop(&inner, &h, session, &mut rx, std::mem::take(&mut queued)).await;
        h.connected.store(false, Ordering::Relaxed);
        *h.session_token.write() = None;
        inner.emit(crate::EngineEvent::LighthouseStatus {
            lighthouse: h.addr.clone(),
            connected: false,
        });
        inner.mark_lighthouse_peers_offline(&h.addr);
        match outcome {
            SessionEnd::Shutdown => return,
            SessionEnd::Lost(e) => {
                tracing::warn!(lighthouse = %h.addr, error = %e, "control channel lost, reconnecting");
                *h.last_error.lock() = Some(e);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

enum SessionEnd {
    Shutdown,
    Lost(String),
}

struct Session {
    stream: NoiseStream<TcpStream>,
    udp_addr: SocketAddr,
}

async fn connect(inner: &Arc<Inner>, h: &LighthouseHandle) -> anyhow::Result<Session> {
    let mut addrs = tokio::net::lookup_host(h.addr.host_port()).await?;
    let addr = addrs
        .find(|a| a.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("no IPv4 address for {}", h.addr.host))?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("connect timed out"))??;
    inner.protect_tcp(&tcp);
    let _ = tcp.set_nodelay(true);
    let hello = ClientHello {
        version: PROTOCOL_VERSION,
        hostname: inner.hostname.clone(),
        os: inner.os.clone(),
    };
    let (stream, server_hello): (NoiseStream<TcpStream>, ServerHello) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        NoiseStream::connect(tcp, &inner.keypair.private.0, &h.addr.key, &hello),
    )
    .await
    .map_err(|_| anyhow::anyhow!("handshake timed out"))??;
    if server_hello.version != PROTOCOL_VERSION {
        anyhow::bail!(
            "lighthouse speaks protocol v{}, we speak v{}",
            server_hello.version,
            PROTOCOL_VERSION
        );
    }
    *h.session_token.write() = Some(server_hello.session_token);
    *h.relay.udp_addr.write() = Some(addr);
    Ok(Session {
        stream,
        udp_addr: addr,
    })
}

async fn session_loop(
    inner: &Arc<Inner>,
    h: &Arc<LighthouseHandle>,
    session: Session,
    rx: &mut mpsc::Receiver<ControlCmd>,
    queued: Vec<ControlCmd>,
) -> SessionEnd {
    let (mut tx, mut rx_noise) = session.stream.into_parts();
    let udp_addr = session.udp_addr;
    let mut pending_joins: HashMap<NetworkId, oneshot::Sender<Result<NetworkInfo, String>>> =
        HashMap::new();
    let mut pending_leaves: HashMap<NetworkId, oneshot::Sender<()>> = HashMap::new();
    let mut join_deadlines: Vec<(NetworkId, Instant)> = Vec::new();

    // Resume whatever we are already a member of, then advertise endpoints.
    if inner.has_memberships_with(&h.addr) {
        if let Err(e) = tx.send(&ToLighthouse::Resume).await {
            return SessionEnd::Lost(e.to_string());
        }
    }
    let mut last_endpoints: Vec<SocketAddr> = Vec::new();
    if let Err(e) = send_endpoints(inner, &mut tx, &mut last_endpoints, true).await {
        return SessionEnd::Lost(e.to_string());
    }
    send_probe(inner, h, udp_addr);

    // Replay commands that arrived while we were (re)connecting.
    for cmd in queued {
        match cmd {
            ControlCmd::Join {
                network,
                token,
                reply,
            } => {
                pending_joins.insert(network, reply);
                join_deadlines.push((network, Instant::now() + JOIN_TIMEOUT));
                if let Err(e) = tx.send(&ToLighthouse::Join { network, token }).await {
                    return SessionEnd::Lost(e.to_string());
                }
            }
            ControlCmd::Leave { network, reply } => {
                pending_leaves.insert(network, reply);
                if let Err(e) = tx.send(&ToLighthouse::Leave { network }).await {
                    return SessionEnd::Lost(e.to_string());
                }
            }
            _ => {}
        }
    }

    let (incoming_tx, mut incoming) = mpsc::channel::<Result<FromLighthouse, String>>(64);
    let reader = tokio::spawn(async move {
        loop {
            match rx_noise.recv::<FromLighthouse>().await {
                Ok(m) => {
                    if incoming_tx.send(Ok(m)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = incoming_tx.send(Err(e.to_string())).await;
                    break;
                }
            }
        }
    });

    let mut ping = tokio::time::interval(PING_EVERY);
    let mut probe = tokio::time::interval(PROBE_EVERY);
    let mut endpoints = tokio::time::interval(ENDPOINTS_EVERY);
    let mut nonce = 0u64;

    let end = loop {
        tokio::select! {
            _ = ping.tick() => {
                nonce = nonce.wrapping_add(1);
                if let Err(e) = tx.send(&ToLighthouse::Ping { nonce }).await { break SessionEnd::Lost(e.to_string()); }
                let now = Instant::now();
                join_deadlines.retain(|(net, deadline)| {
                    if now >= *deadline {
                        if let Some(reply) = pending_joins.remove(net) { let _ = reply.send(Err("join timed out".into())); }
                        false
                    } else { true }
                });
            }
            _ = probe.tick() => { send_probe(inner, h, udp_addr); }
            _ = endpoints.tick() => {
                if let Err(e) = send_endpoints(inner, &mut tx, &mut last_endpoints, false).await { break SessionEnd::Lost(e.to_string()); }
            }
            cmd = rx.recv() => {
                match cmd {
                    None | Some(ControlCmd::Shutdown) => break SessionEnd::Shutdown,
                    Some(ControlCmd::Join { network, token, reply }) => {
                        pending_joins.insert(network, reply);
                        join_deadlines.push((network, Instant::now() + JOIN_TIMEOUT));
                        if let Err(e) = tx.send(&ToLighthouse::Join { network, token }).await { break SessionEnd::Lost(e.to_string()); }
                    }
                    Some(ControlCmd::Leave { network, reply }) => {
                        pending_leaves.insert(network, reply);
                        if let Err(e) = tx.send(&ToLighthouse::Leave { network }).await { break SessionEnd::Lost(e.to_string()); }
                    }
                    Some(ControlCmd::Punch { network, target }) => {
                        if let Err(e) = tx.send(&ToLighthouse::Punch { network, target }).await { break SessionEnd::Lost(e.to_string()); }
                    }
                    Some(ControlCmd::RefreshEndpoints) => {
                        if let Err(e) = send_endpoints(inner, &mut tx, &mut last_endpoints, true).await { break SessionEnd::Lost(e.to_string()); }
                        send_probe(inner, h, udp_addr);
                    }
                }
            }
            msg = incoming.recv() => {
                let msg = match msg {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => break SessionEnd::Lost(e),
                    None => break SessionEnd::Lost("reader stopped".into()),
                };
                match msg {
                    FromLighthouse::Joined { network } => {
                        inner.membership_added(&h.addr, network.clone());
                        if let Some(reply) = pending_joins.remove(&network.id) { let _ = reply.send(Ok(network)); }
                        // A fresh membership changes our own addresses; re-advertise so
                        // the overlay address is excluded from candidates.
                        if let Err(e) = send_endpoints(inner, &mut tx, &mut last_endpoints, true).await { break SessionEnd::Lost(e.to_string()); }
                    }
                    FromLighthouse::JoinFailed { network, reason } => {
                        if let Some(reply) = pending_joins.remove(&network) { let _ = reply.send(Err(reason)); }
                    }
                    FromLighthouse::Left { network } => {
                        inner.membership_removed(&h.addr, network);
                        if let Some(reply) = pending_leaves.remove(&network) { let _ = reply.send(()); }
                    }
                    FromLighthouse::Removed { network, reason } => {
                        tracing::warn!(network = %network, %reason, "removed from network");
                        inner.membership_removed(&h.addr, network);
                    }
                    FromLighthouse::NetworkState { network, peers } => {
                        inner.network_state(h, network, peers);
                    }
                    FromLighthouse::PunchRequest { network: _, from, endpoints } => {
                        inner.punch_towards(&from, &endpoints);
                    }
                    FromLighthouse::Pong { .. } => {}
                    FromLighthouse::Error { message } => {
                        tracing::warn!(lighthouse = %h.addr, %message, "lighthouse error");
                    }
                }
            }
        }
    };
    reader.abort();
    for (_, reply) in pending_leaves.drain() {
        let _ = reply.send(());
    }
    end
}

async fn send_endpoints(
    inner: &Arc<Inner>,
    tx: &mut ig_proto::noise::NoiseSender<TcpStream>,
    last: &mut Vec<SocketAddr>,
    force: bool,
) -> Result<(), ig_proto::noise::NoiseError> {
    let current = inner.local_candidates();
    if force || current != *last {
        tx.send(&ToLighthouse::Endpoints {
            local: current.clone(),
        })
        .await?;
        *last = current;
    }
    Ok(())
}

fn send_probe(inner: &Arc<Inner>, h: &LighthouseHandle, udp_addr: SocketAddr) {
    let Some(token) = *h.session_token.read() else {
        return;
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let frame = disco::encode_probe(&inner.keypair.public, ts, &token);
    inner.udp_send(&frame, udp_addr);
}
