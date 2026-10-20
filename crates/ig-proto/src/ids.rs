//! Stable identifiers. Both serialize as raw bytes in binary formats (postcard)
//! and as readable strings in human formats (JSON).

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// A node is identified by its X25519 public key. The same key is used for the
/// control channel (Noise IK) and for WireGuard, so the identity is cryptographic:
/// nothing but possession of the private key proves you are this node.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Short prefix for logs and tables.
    pub fn short(&self) -> String {
        let s = self.to_string();
        s[..8].to_string()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid identifier: {0}")]
pub struct ParseIdError(pub String);

impl FromStr for NodeId {
    type Err = ParseIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|e| ParseIdError(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ParseIdError("node id must be 32 bytes".into()))?;
        Ok(NodeId(arr))
    }
}

impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse().map_err(D::Error::custom)
        } else {
            let b: serde_bytes_shim::Bytes = Deserialize::deserialize(d)?;
            let arr: [u8; 32] = b
                .0
                .try_into()
                .map_err(|_| D::Error::custom("node id must be 32 bytes"))?;
            Ok(NodeId(arr))
        }
    }
}

/// Identifier of an overlay network on a lighthouse. Random, 8 bytes, shown as hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetworkId(pub [u8; 8]);

impl NetworkId {
    pub fn random() -> Self {
        NetworkId(crate::random_array())
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetworkId({self})")
    }
}

impl FromStr for NetworkId {
    type Err = ParseIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() != 16 {
            return Err(ParseIdError("network id must be 16 hex characters".into()));
        }
        let mut out = [0u8; 8];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let h = std::str::from_utf8(chunk).map_err(|e| ParseIdError(e.to_string()))?;
            out[i] = u8::from_str_radix(h, 16).map_err(|e| ParseIdError(e.to_string()))?;
        }
        Ok(NetworkId(out))
    }
}

impl Serialize for NetworkId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for NetworkId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse().map_err(D::Error::custom)
        } else {
            let b: serde_bytes_shim::Bytes = Deserialize::deserialize(d)?;
            let arr: [u8; 8] = b
                .0
                .try_into()
                .map_err(|_| D::Error::custom("network id must be 8 bytes"))?;
            Ok(NetworkId(arr))
        }
    }
}

/// Minimal byte-buffer deserializer so we do not need the `serde_bytes` crate.
mod serde_bytes_shim {
    use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
    use std::fmt;

    pub struct Bytes(pub Vec<u8>);

    impl<'de> Deserialize<'de> for Bytes {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Bytes;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Bytes, E> {
                    Ok(Bytes(v.to_vec()))
                }
                fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                    Ok(Bytes(v))
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Bytes, A::Error> {
                    let mut out = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        out.push(b);
                    }
                    Ok(Bytes(out))
                }
            }
            d.deserialize_byte_buf(V)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_roundtrips_in_both_formats() {
        let id = NodeId(crate::random_array());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<NodeId>(&json).unwrap(), id);
        let bin = postcard::to_allocvec(&id).unwrap();
        assert_eq!(bin.len(), 33, "postcard: 1 length byte + 32");
        assert_eq!(postcard::from_bytes::<NodeId>(&bin).unwrap(), id);
        assert_eq!(id.to_string().parse::<NodeId>().unwrap(), id);
    }

    #[test]
    fn network_id_roundtrips() {
        let id = NetworkId::random();
        assert_eq!(id.to_string().parse::<NetworkId>().unwrap(), id);
        let bin = postcard::to_allocvec(&id).unwrap();
        assert_eq!(postcard::from_bytes::<NetworkId>(&bin).unwrap(), id);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<NetworkId>(&json).unwrap(), id);
    }
}
