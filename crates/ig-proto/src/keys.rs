//! X25519 identity keys. One keypair per node and per lighthouse.

use crate::NodeId;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

/// A private key, stored as 32 raw bytes. Serializes as base64 in JSON.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKey(#[serde(with = "b64")] pub [u8; 32]);

impl PrivateKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::from(crate::random_array::<32>());
        PrivateKey(secret.to_bytes())
    }

    pub fn public(&self) -> NodeId {
        let secret = StaticSecret::from(self.0);
        NodeId(PublicKey::from(&secret).to_bytes())
    }

    pub fn to_static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.0)
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey(<redacted>, public={})", self.public().short())
    }
}

#[derive(Clone, Debug)]
pub struct Keypair {
    pub private: PrivateKey,
    pub public: NodeId,
}

impl Keypair {
    pub fn generate() -> Self {
        let private = PrivateKey::generate();
        let public = private.public();
        Keypair { private, public }
    }

    pub fn from_private(private: PrivateKey) -> Self {
        let public = private.public();
        Keypair { private, public }
    }
}

mod b64 {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            URL_SAFE_NO_PAD.encode(v).serialize(s)
        } else {
            s.serialize_bytes(v)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error;
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let v = URL_SAFE_NO_PAD.decode(s).map_err(D::Error::custom)?;
            v.try_into().map_err(|_| D::Error::custom("key must be 32 bytes"))
        } else {
            let v = <Vec<u8>>::deserialize(d)?;
            v.try_into().map_err(|_| D::Error::custom("key must be 32 bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_is_stable() {
        let kp = Keypair::generate();
        assert_eq!(kp.private.public(), kp.public);
        let json = serde_json::to_string(&kp.private).unwrap();
        let back: PrivateKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back.public(), kp.public);
    }
}
