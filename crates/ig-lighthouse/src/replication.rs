//! Replica side of store replication: keep a Noise connection to the primary,
//! apply every snapshot it sends, and carry proxied node requests.

use crate::server::Inner;
use ig_proto::control::{ClientHello, LighthouseRef, ServerHello};
use ig_proto::noise::NoiseStream;
use ig_proto::replication::{FromPrimary, ToPrimary};
use ig_proto::PROTOCOL_VERSION;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub async fn run_replica(inner: Arc<Inner>, primary: LighthouseRef) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match session(&inner, &primary).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(e) => {
                tracing::warn!(primary = %format!("{}:{}", primary.host, primary.port), error = %e, "replication link down");
            }
        }
        inner.primary_link_lost();
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn session(inner: &Arc<Inner>, primary: &LighthouseRef) -> anyhow::Result<()> {
    let addr = tokio::net::lookup_host((primary.host.as_str(), primary.port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve {}", primary.host))?;
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await??;
    let _ = tcp.set_nodelay(true);
    let hello = ClientHello {
        version: PROTOCOL_VERSION,
        hostname: inner.config.name.clone(),
        os: "lighthouse".into(),
        gateway: false,
        replica: true,
    };
    let (stream, _hello): (NoiseStream<TcpStream>, ServerHello) = tokio::time::timeout(
        Duration::from_secs(10),
        NoiseStream::connect(tcp, &inner.config.keypair.private.0, &primary.key, &hello),
    )
    .await??;
    tracing::info!(primary = %format!("{}:{}", primary.host, primary.port), "replication link up");
    let (mut tx, mut rx) = stream.into_parts();
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ToPrimary>(256);
    inner.primary_link_up(cmd_tx);
    let writer = tokio::spawn(async move {
        while let Some(m) = cmd_rx.recv().await {
            if tx.send(&m).await.is_err() {
                break;
            }
        }
    });
    let mut ping = tokio::time::interval(Duration::from_secs(15));
    let result: anyhow::Result<()> = async {
        loop {
            tokio::select! {
                _ = ping.tick() => {
                    inner.proxy_to_primary(ToPrimary::Ping).await;
                }
                m = rx.recv::<FromPrimary>() => {
                    match m? {
                        FromPrimary::Snapshot { store_json } => inner.apply_snapshot(&store_json)?,
                        FromPrimary::ProxyReply { node, msg } => inner.send_to(&node, msg),
                        FromPrimary::Pong => {}
                    }
                }
            }
        }
    }
    .await;
    writer.abort();
    result
}
