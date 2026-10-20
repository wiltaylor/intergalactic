//! Shared protocol definitions for Intergalactic.
//!
//! Every component (lighthouse, desktop node, mobile core, CLI) speaks the
//! types in this crate. There are four wire surfaces:
//!
//! * [`control`]  – reliable, Noise-encrypted TCP channel between a node and a
//!   lighthouse. Carries joins, peer lists and hole-punch requests.
//! * [`disco`]    – small UDP datagrams between a node and a lighthouse used to
//!   discover the node's public (reflexive) address and to relay WireGuard
//!   traffic when a direct path cannot be punched.
//! * [`admin`]    – local JSON protocol between the `ig-lighthouse` CLI and the
//!   lighthouse daemon.
//! * [`ipc`]      – local JSON protocol between the `ig` CLI and the node daemon.
//!
//! The data plane itself is plain WireGuard (boringtun) and is not described here.

pub mod admin;
pub mod control;
pub mod disco;
pub mod framing;
pub mod ids;
pub mod invite;
pub mod ipc;
pub mod keys;
pub mod noise;
pub mod policy;
pub mod udp;

pub use ids::{NetworkId, NodeId};
pub use invite::Invite;
pub use keys::{Keypair, PrivateKey};
pub use policy::{Policy, Proto, RelayLimit, Rule};

/// Default DNS suffix for peer names. `.internal` is reserved for private use.
pub const DEFAULT_DNS_DOMAIN: &str = "ig.internal";

/// Protocol version carried in the control-channel hello.
pub const PROTOCOL_VERSION: u16 = 1;

/// Default port for both the TCP control channel and the UDP disco/relay socket of a lighthouse.
pub const DEFAULT_LIGHTHOUSE_PORT: u16 = 7777;

/// MTU configured on overlay interfaces. Leaves room for WireGuard (32 B), the
/// relay header (37 B) and outer IPv4/UDP (28 B) inside a 1500 byte path.
pub const OVERLAY_MTU: u16 = 1380;

/// Fill a buffer with cryptographically secure random bytes.
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("operating system random source unavailable");
}

/// Convenience: a fresh random array.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    random_bytes(&mut out);
    out
}
