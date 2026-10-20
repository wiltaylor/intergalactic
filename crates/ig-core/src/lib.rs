//! The Intergalactic node engine.
//!
//! The engine is platform-neutral. It owns one UDP socket, one WireGuard
//! session per peer, and zero or more TUN devices that the embedding program
//! attaches. Everything that touches the operating system in a platform-specific
//! way (creating TUN interfaces, protecting sockets on Android, persisting state)
//! is done by the embedder in response to [`EngineEvent`]s.
//!
//! ```text
//!  TUN(s) ──IP packets──▶ Engine ──WireGuard/UDP──▶ peers (direct)
//!                           │                     └▶ lighthouse (relay)
//!                           └──Noise/TCP──▶ lighthouse (control)
//! ```

pub mod dns;
pub mod endpoints;
pub mod engine;
pub mod filter;
pub mod nat;
pub mod packet;
pub mod peer;
pub mod state;
pub mod tun;
pub mod tunnel;

mod control;

pub use engine::{Engine, EngineConfig, EngineError, EngineEvent, NoProtector, SocketProtector};
pub use state::{LighthouseAddr, Membership, NodeState};
pub use tun::{TunDevice, TunScope};

pub use ig_proto;
