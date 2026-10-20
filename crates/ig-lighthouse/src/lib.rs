//! The lighthouse is the only piece of Intergalactic that needs a public address.
//! It does three things and nothing more:
//!
//! 1. **Coordination** – it knows which nodes belong to which networks, hands out
//!    overlay addresses, and pushes the member list to every online node.
//! 2. **NAT traversal** – it tells each node its public UDP address and forwards
//!    hole-punch requests so two nodes behind NATs start sending simultaneously.
//! 3. **Relay** – when a direct path is impossible it forwards the encrypted
//!    WireGuard datagrams. It never holds keys for the data plane and cannot
//!    read the traffic it relays.

pub mod admin_socket;
pub mod replication;
pub mod server;
pub mod store;

pub use server::{Lighthouse, LighthouseConfig};
