//! Outbound side of lighthouse peering: keep a Noise connection to every other
//! lighthouse in the store. Both lighthouses dial each other; a pair may hold
//! two links, which is harmless because state exchange is idempotent.

use crate::server::Inner;
use crate::store::LighthouseRecord;
use ig_proto::control::{ClientHello, ServerHello};
use ig_proto::noise::NoiseStream;
use ig_proto::{NodeId, PROTOCOL_VERSION};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

/// Dialers by peer key. Dropped (when `run_peers` is aborted on shutdown), it
/// aborts every dialer, so no link outlives the lighthouse.
#[derive(Default)]
struct Dialers(HashMap<NodeId, (LighthouseRecord, JoinHandle<()>)>);

impl Drop for Dialers {
    fn drop(&mut self) {
        for (_, (_, h)) in self.0.drain() {
            h.abort();
        }
    }
}

/// Start and stop dialers as lighthouses are added, changed and removed.
pub async fn run_peers(inner: Arc<Inner>) {
    let me = inner.config.keypair.public;
    let mut dialers = Dialers::default();
    let dialers = &mut dialers.0;
    loop {
        let wanted: Vec<LighthouseRecord> = inner
            .lighthouse_records()
            .into_iter()
            .filter(|l| l.key != me)
            .collect();
        let stale: Vec<NodeId> = dialers
            .iter()
            .filter(|(k, (rec, _))| {
                !wanted
                    .iter()
                    .any(|w| w.key == **k && w.host == rec.host && w.port == rec.port)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            if let Some((_, h)) = dialers.remove(&k) {
                h.abort();
            }
        }
        for rec in wanted {
            if dialers.contains_key(&rec.key) {
                continue;
            }
            let h = tokio::spawn(dial_loop(inner.clone(), rec.clone()));
            dialers.insert(rec.key, (rec, h));
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn dial_loop(inner: Arc<Inner>, rec: LighthouseRecord) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match session(&inner, &rec).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(e) => {
                tracing::debug!(lighthouse = %rec.name, error = %e, "peer link down");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn session(inner: &Arc<Inner>, rec: &LighthouseRecord) -> anyhow::Result<()> {
    let addr = tokio::net::lookup_host((rec.host.as_str(), rec.port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve {}", rec.host))?;
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await??;
    let _ = tcp.set_nodelay(true);
    let hello = ClientHello {
        version: PROTOCOL_VERSION,
        hostname: inner.config.name.clone(),
        os: "lighthouse".into(),
        gateway: false,
        peer: true,
    };
    let (stream, _hello): (NoiseStream<TcpStream>, ServerHello) = tokio::time::timeout(
        Duration::from_secs(10),
        NoiseStream::connect(tcp, &inner.config.keypair.private.0, &rec.key, &hello),
    )
    .await??;
    crate::server::peer_session(inner.clone(), stream, rec.key).await
}
