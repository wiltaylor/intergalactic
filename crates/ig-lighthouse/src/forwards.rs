//! Public port forwards: listeners on the lighthouse, streams to nodes over
//! their tunnel channels.

use ig_proto::tunnel::{ForwardInfo, ForwardProto, TunnelMsg, CHUNK};
use ig_proto::NodeId;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const UDP_IDLE: Duration = Duration::from_secs(60);
/// Per-stream buffer of frames waiting for the socket writer.
const STREAM_QUEUE: usize = 64;

/// A node's tunnel channel as seen by the lighthouse.
pub struct TunnelSession {
    pub node: NodeId,
    pub tx: mpsc::Sender<TunnelMsg>,
    pub abort: tokio::sync::Notify,
}

struct Listener {
    info: ForwardInfo,
    task: JoinHandle<()>,
}

/// Frames from a node for one public socket.
type StreamSink = mpsc::Sender<Vec<u8>>;

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
pub struct Forwards {
    listeners: Mutex<HashMap<String, Listener>>,
    tunnels: RwLock<HashMap<NodeId, Arc<TunnelSession>>>,
    /// (node, stream) -> frames from the node for the public socket.
    streams: Mutex<HashMap<(NodeId, u32), StreamSink>>,
    /// forward id -> open streams, for `forward list`.
    active: Mutex<HashMap<String, usize>>,
    next_stream: AtomicU32,
}

impl Forwards {
    pub fn tunnel_connected(&self, s: Arc<TunnelSession>) -> Option<Arc<TunnelSession>> {
        self.tunnels.write().insert(s.node, s)
    }

    pub fn tunnel_disconnected(&self, node: &NodeId, s: &Arc<TunnelSession>) {
        let mut t = self.tunnels.write();
        if t.get(node).is_some_and(|cur| Arc::ptr_eq(cur, s)) {
            t.remove(node);
        }
        drop(t);
        // Dropping the senders ends every socket task of this node.
        self.streams.lock().retain(|(n, _), _| n != node);
    }

    pub fn has_tunnel(&self, node: &NodeId) -> bool {
        self.tunnels.read().contains_key(node)
    }

    pub fn active_streams(&self, forward: &str) -> usize {
        self.active.lock().get(forward).copied().unwrap_or(0)
    }

    /// A frame from a node's tunnel channel.
    pub async fn from_node(&self, node: NodeId, msg: TunnelMsg) {
        match msg {
            TunnelMsg::Data { stream, data } => {
                let tx = self.streams.lock().get(&(node, stream)).cloned();
                if let Some(tx) = tx {
                    let _ = tx.send(data).await;
                }
            }
            TunnelMsg::Close { stream, .. } => {
                self.streams.lock().remove(&(node, stream));
            }
            TunnelMsg::Open { .. } | TunnelMsg::Ping => {}
        }
    }

    /// Make the set of listeners match `wanted`.
    pub fn reconcile(self: &Arc<Self>, wanted: Vec<ForwardInfo>) {
        let mut ls = self.listeners.lock();
        let ids: std::collections::HashSet<&str> = wanted.iter().map(|f| f.id.as_str()).collect();
        ls.retain(|id, l| {
            let keep = ids.contains(id.as_str()) && wanted.iter().any(|w| w.id == *id && w.public_port == l.info.public_port && w.proto == l.info.proto);
            if !keep {
                tracing::info!(forward = %id, port = l.info.public_port, "forward listener removed");
            }
            keep
        });
        for f in wanted {
            if let Some(existing) = ls.get_mut(&f.id) {
                // Target or node may have changed; refresh the copy the tasks read.
                existing.info = f;
                continue;
            }
            let me = self.clone();
            let info = f.clone();
            let task = match f.proto {
                ForwardProto::Tcp => tokio::spawn(async move { me.serve_tcp(info).await }),
                ForwardProto::Udp => tokio::spawn(async move { me.serve_udp(info).await }),
            };
            tracing::info!(forward = %f.id, port = f.public_port, proto = %f.proto, node = %f.node.short(), target = %f.target, "forward listener added");
            ls.insert(f.id.clone(), Listener { info: f, task });
        }
    }

    fn current_info(&self, id: &str) -> Option<ForwardInfo> {
        self.listeners.lock().get(id).map(|l| l.info.clone())
    }

    fn open_stream(&self, node: NodeId) -> (u32, mpsc::Receiver<Vec<u8>>) {
        let id = self.next_stream.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        self.streams.lock().insert((node, id), tx);
        (id, rx)
    }

    fn close_stream(&self, node: NodeId, id: u32, forward: &str) {
        self.streams.lock().remove(&(node, id));
        let mut a = self.active.lock();
        if let Some(n) = a.get_mut(forward) {
            *n = n.saturating_sub(1);
        }
    }

    async fn serve_tcp(self: Arc<Self>, info: ForwardInfo) {
        let listener = match TcpListener::bind(("::", info.public_port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(port = info.public_port, error = %e, "cannot bind forward port");
                return;
            }
        };
        loop {
            let Ok((sock, remote)) = listener.accept().await else {
                continue;
            };
            let me = self.clone();
            let id = info.id.clone();
            tokio::spawn(async move {
                let Some(info) = me.current_info(&id) else {
                    return;
                };
                let Some(tunnel) = me.tunnels.read().get(&info.node).cloned() else {
                    tracing::debug!(forward = %info.id, "connection refused: node has no tunnel channel");
                    return;
                };
                let (stream, mut rx) = me.open_stream(info.node);
                *me.active.lock().entry(info.id.clone()).or_insert(0) += 1;
                let opened = tunnel
                    .tx
                    .send(TunnelMsg::Open {
                        stream,
                        forward: info.id.clone(),
                        proto: ForwardProto::Tcp,
                        target: info.target.clone(),
                        remote: ig_proto::udp::canonical(remote),
                    })
                    .await;
                if opened.is_err() {
                    me.close_stream(info.node, stream, &info.id);
                    return;
                }
                let (mut rd, mut wr) = sock.into_split();
                let tx = tunnel.tx.clone();
                let to_node = async move {
                    let mut buf = vec![0u8; CHUNK];
                    loop {
                        match rd.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tx
                                    .send(TunnelMsg::Data {
                                        stream,
                                        data: buf[..n].to_vec(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                };
                let from_node = async move {
                    while let Some(data) = rx.recv().await {
                        if wr.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    let _ = wr.shutdown().await;
                };
                tokio::select! {
                    _ = to_node => {}
                    _ = from_node => {}
                }
                let _ = tunnel
                    .tx
                    .send(TunnelMsg::Close {
                        stream,
                        reason: "closed".into(),
                    })
                    .await;
                me.close_stream(info.node, stream, &info.id);
            });
        }
    }

    async fn serve_udp(self: Arc<Self>, info: ForwardInfo) {
        let sock = match UdpSocket::bind(("::", info.public_port)).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::error!(port = info.public_port, error = %e, "cannot bind forward port");
                return;
            }
        };
        // remote -> (stream id, last activity)
        let mut flows: HashMap<SocketAddr, (u32, std::time::Instant)> = HashMap::new();
        let mut buf = vec![0u8; 65536];
        let mut sweep = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                r = sock.recv_from(&mut buf) => {
                    let Ok((n, remote)) = r else { continue };
                    let remote = ig_proto::udp::canonical(remote);
                    let Some(cur) = self.current_info(&info.id) else { return };
                    let Some(tunnel) = self.tunnels.read().get(&cur.node).cloned() else { continue };
                    let now = std::time::Instant::now();
                    let stream = match flows.get_mut(&remote) {
                        Some((id, last)) => { *last = now; *id }
                        None => {
                            let (id, mut rx) = self.open_stream(cur.node);
                            *self.active.lock().entry(cur.id.clone()).or_insert(0) += 1;
                            flows.insert(remote, (id, now));
                            if tunnel.tx.send(TunnelMsg::Open { stream: id, forward: cur.id.clone(), proto: ForwardProto::Udp, target: cur.target.clone(), remote }).await.is_err() {
                                continue;
                            }
                            // Replies for this remote peer.
                            let s = sock.clone();
                            let wire = ig_proto::udp::to_wire(remote, true);
                            tokio::spawn(async move {
                                while let Some(data) = rx.recv().await {
                                    let _ = s.send_to(&data, wire).await;
                                }
                            });
                            id
                        }
                    };
                    let _ = tunnel.tx.send(TunnelMsg::Data { stream, data: buf[..n].to_vec() }).await;
                }
                _ = sweep.tick() => {
                    let now = std::time::Instant::now();
                    let Some(cur) = self.current_info(&info.id) else { return };
                    let tunnel = self.tunnels.read().get(&cur.node).cloned();
                    let expired: Vec<SocketAddr> = flows.iter().filter(|(_, (_, t))| now.duration_since(*t) > UDP_IDLE).map(|(r, _)| *r).collect();
                    for r in expired {
                        if let Some((id, _)) = flows.remove(&r) {
                            if let Some(t) = &tunnel {
                                let _ = t.tx.send(TunnelMsg::Close { stream: id, reason: "idle".into() }).await;
                            }
                            self.close_stream(cur.node, id, &cur.id);
                        }
                    }
                }
            }
        }
    }
}
