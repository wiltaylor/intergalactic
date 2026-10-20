//! Node side of public port forwards: the tunnel channel to a lighthouse.
//!
//! One extra Noise/TCP connection per lighthouse. The lighthouse opens a stream
//! for every public connection; we connect to the forward's target and pump
//! bytes both ways. Reconnects with backoff while the control channel is up.

use crate::engine::Inner;
use crate::state::LighthouseAddr;
use ig_proto::control::{ClientHello, ServerHello};
use ig_proto::noise::{NoiseSender, NoiseStream};
use ig_proto::tunnel::{ForwardProto, TunnelMsg, CHUNK};
use ig_proto::PROTOCOL_VERSION;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE: Duration = Duration::from_secs(60);

type Sender = Arc<Mutex<NoiseSender<TcpStream>>>;

pub async fn run(inner: Arc<Inner>, lh: LighthouseAddr) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match session(&inner, &lh).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(e) => {
                tracing::debug!(lighthouse = %lh, error = %e, "tunnel channel ended");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn session(inner: &Arc<Inner>, lh: &LighthouseAddr) -> anyhow::Result<()> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(lh.host_port()).await?.collect();
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| anyhow::anyhow!("no address for {}", lh.host))?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await??;
    inner.protect_tcp(&tcp);
    let _ = tcp.set_nodelay(true);
    let hello = ClientHello {
        version: PROTOCOL_VERSION,
        hostname: inner.hostname.clone(),
        os: inner.os.clone(),
        gateway: inner.gateway,
        tunnel: true,
    };
    let (stream, _server): (NoiseStream<TcpStream>, ServerHello) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        NoiseStream::connect(tcp, &inner.keypair.private.0, &lh.key, &hello),
    )
    .await??;
    tracing::info!(lighthouse = %lh, "tunnel channel up");
    let (tx, mut rx) = stream.into_parts();
    let tx: Sender = Arc::new(Mutex::new(tx));
    let mut streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = ping.tick() => {
                tx.lock().await.send(&TunnelMsg::Ping).await?;
                streams.retain(|_, s| !s.is_closed());
            }
            msg = rx.recv::<TunnelMsg>() => {
                match msg? {
                    TunnelMsg::Open { stream, forward, proto, target, remote } => {
                        tracing::info!(%forward, %proto, %target, %remote, "forwarded connection");
                        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
                        streams.insert(stream, data_tx);
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let result = match proto {
                                ForwardProto::Tcp => pump_tcp(tx.clone(), stream, &target, data_rx).await,
                                ForwardProto::Udp => pump_udp(tx.clone(), stream, &target, data_rx).await,
                            };
                            let reason = match result {
                                Ok(()) => "closed".to_string(),
                                Err(e) => e.to_string(),
                            };
                            let _ = tx.lock().await.send(&TunnelMsg::Close { stream, reason }).await;
                        });
                    }
                    TunnelMsg::Data { stream, data } => {
                        if let Some(s) = streams.get(&stream) {
                            if s.send(data).await.is_err() {
                                streams.remove(&stream);
                            }
                        }
                    }
                    TunnelMsg::Close { stream, .. } => {
                        streams.remove(&stream);
                    }
                    TunnelMsg::Ping => {}
                }
            }
        }
    }
}

async fn pump_tcp(
    tx: Sender,
    stream: u32,
    target: &str,
    mut from_lh: mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    let sock = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| anyhow::anyhow!("connect to {target} timed out"))??;
    let _ = sock.set_nodelay(true);
    let (mut rd, mut wr) = sock.into_split();
    let to_lh = async {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx
                        .lock()
                        .await
                        .send(&TunnelMsg::Data {
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
    let from_lh_task = async {
        while let Some(data) = from_lh.recv().await {
            if wr.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    };
    tokio::select! {
        _ = to_lh => {}
        _ = from_lh_task => {}
    }
    Ok(())
}

async fn pump_udp(
    tx: Sender,
    stream: u32,
    target: &str,
    mut from_lh: mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    let target_addr: std::net::SocketAddr = tokio::net::lookup_host(target)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve {target}"))?;
    let bind: std::net::SocketAddr = if target_addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(target_addr).await?;
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = sock.recv(&mut buf) => {
                let n = r?;
                tx.lock().await.send(&TunnelMsg::Data { stream, data: buf[..n].to_vec() }).await?;
            }
            d = from_lh.recv() => {
                match d {
                    Some(data) => { let _ = sock.send(&data).await; }
                    None => return Ok(()),
                }
            }
            _ = tokio::time::sleep(UDP_IDLE) => return Ok(()),
        }
    }
}
