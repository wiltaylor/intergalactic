//! State exchange between lighthouses.
//!
//! Lighthouses are peers: there is no primary. Two lighthouses that know each
//! other hold a Noise control connection (the hello sets `peer = true`) and
//! send each other their whole store whenever it changes. Each side merges what
//! it receives (see the lighthouse's `Store::merge`), so both converge after one
//! exchange. The store is small (members, invites, devices, forwards), so full
//! state is simpler and safer than deltas.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Gossip {
    /// The sender's whole store as JSON.
    State {
        store_json: Vec<u8>,
    },
    Ping,
    Pong,
}
