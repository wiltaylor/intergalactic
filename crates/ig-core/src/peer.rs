//! Per-peer state: the WireGuard session plus everything needed to pick a path.

use crate::filter::PeerFilter;
use boringtun::noise::Tunn;
use ig_proto::ipc::PeerPath;
use ig_proto::{NetworkId, NodeId};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a direct path may go without receiving anything (while we keep
/// sending) before we fall back to the relay and start punching again.
pub const DIRECT_STALE: Duration = Duration::from_secs(30);
/// Minimum interval between two punch attempts towards the same peer.
pub const PUNCH_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum candidate endpoints kept per peer.
pub const MAX_CANDIDATES: usize = 16;

/// Shared, lock-free view of a lighthouse the engine is connected to. Peers hold
/// one so they can relay through the right place without consulting the engine.
pub struct RelayPoint {
    pub addr: crate::state::LighthouseAddr,
    pub udp_addr: parking_lot::RwLock<Option<SocketAddr>>,
    /// Command channel of the control task, used to request hole punches.
    pub cmd: tokio::sync::mpsc::Sender<crate::control::ControlCmd>,
}

pub struct Peer {
    pub id: NodeId,
    /// boringtun session index; `receiver_idx >> 8` of inbound packets maps back here.
    pub index: u32,
    pub hostname: String,
    pub online: bool,
    pub tunn: Tunn,
    /// Address of the peer in each network we share with it.
    pub addresses: HashMap<NetworkId, Ipv4Addr>,
    /// Endpoints worth trying for a direct path.
    pub candidates: Vec<SocketAddr>,
    /// Endpoint that proved to work (we received authenticated traffic from it).
    pub direct: Option<SocketAddr>,
    pub last_direct_rx: Option<Instant>,
    pub last_relay_rx: Option<Instant>,
    pub last_tx: Option<Instant>,
    pub last_punch: Option<Instant>,
    /// Lighthouse that can relay for this peer and forward punch requests.
    pub relay: Option<Arc<RelayPoint>>,
    /// Network through which the relay lighthouse knows the peer.
    pub relay_network: Option<NetworkId>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub filter: PeerFilter,
}

impl Peer {
    pub fn path(&self) -> PeerPath {
        if self.direct.is_some() {
            PeerPath::Direct
        } else if self.last_relay_rx.is_some() && self.tunn.time_since_last_handshake().is_some() {
            PeerPath::Relay
        } else {
            PeerPath::None
        }
    }

    pub fn merge_candidates(&mut self, more: &[SocketAddr]) {
        for c in more {
            if !self.candidates.contains(c) {
                self.candidates.push(*c);
            }
        }
        if self.candidates.len() > MAX_CANDIDATES {
            let excess = self.candidates.len() - MAX_CANDIDATES;
            self.candidates.drain(0..excess);
        }
    }

    /// Replace candidates learned through one lighthouse view while keeping the
    /// confirmed direct endpoint in the list.
    pub fn set_candidates(&mut self, list: &[SocketAddr]) {
        self.candidates = list.iter().copied().take(MAX_CANDIDATES).collect();
        if let Some(d) = self.direct {
            if !self.candidates.contains(&d) {
                self.candidates.push(d);
            }
        }
    }

    /// Called from the timer loop. Returns true when the direct path was dropped.
    pub fn expire_direct(&mut self, now: Instant) -> bool {
        let Some(_) = self.direct else { return false };
        let sent_recently = self
            .last_tx
            .is_some_and(|t| now.duration_since(t) < DIRECT_STALE);
        let heard_recently = self
            .last_direct_rx
            .is_some_and(|t| now.duration_since(t) < DIRECT_STALE);
        if sent_recently && !heard_recently {
            self.direct = None;
            return true;
        }
        false
    }

    pub fn may_punch(&mut self, now: Instant) -> bool {
        if self
            .last_punch
            .is_none_or(|t| now.duration_since(t) >= PUNCH_INTERVAL)
        {
            self.last_punch = Some(now);
            true
        } else {
            false
        }
    }
}
