//! Invite strings. An invite tells a node everything it needs to join one network:
//! where the lighthouse is, which key to expect from it, which network to join and
//! a secret token that proves the holder was invited.
//!
//! Format: `ig1:<base64url(postcard(InviteBody))>`. Short enough for a QR code.

use crate::{NetworkId, NodeId};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub const INVITE_PREFIX: &str = "ig1:";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// Host name or IP of the lighthouse as reachable from the public internet.
    pub host: String,
    /// Port used for both TCP control and UDP disco/relay.
    pub port: u16,
    /// Lighthouse static public key. Pins the server identity.
    pub lighthouse: NodeId,
    pub network: NetworkId,
    /// Human-readable network name, informational only.
    pub network_name: String,
    /// Secret proving the invite. The lighthouse stores only a hash of it.
    pub token: [u8; 16],
    /// Additional lighthouses serving the network (replicas). `host`/`port`/
    /// `lighthouse` above describe the primary.
    #[serde(default)]
    pub extra_lighthouses: Vec<crate::control::LighthouseRef>,
}

impl Invite {
    pub fn encode(&self) -> String {
        let body = postcard::to_allocvec(self).expect("invite serializes");
        format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(body))
    }

    /// Hash stored by the lighthouse so a stolen state file does not leak live tokens.
    pub fn token_hash(token: &[u8; 16]) -> [u8; 32] {
        blake3::derive_key("intergalactic invite token v1", token)
    }
}

impl fmt::Display for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseInviteError {
    #[error("invite must start with `ig1:`")]
    Prefix,
    #[error("invite is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invite body is malformed: {0}")]
    Body(#[from] postcard::Error),
}

impl FromStr for Invite {
    type Err = ParseInviteError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let body = s
            .strip_prefix(INVITE_PREFIX)
            .ok_or(ParseInviteError::Prefix)?;
        let bytes = URL_SAFE_NO_PAD.decode(body)?;
        Ok(postcard::from_bytes(&bytes)?)
    }
}

/// The invite as a QR code drawn with Unicode half blocks, for a terminal.
/// The Android app scans it to join.
pub fn qr_terminal(invite: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(invite.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Light)
        .light_color(qrcode::render::unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

/// The invite as an SVG QR code, for a web page or a document.
pub fn qr_svg(invite: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(invite.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(320, 320)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip() {
        let inv = Invite {
            host: "lh.example.com".into(),
            port: 7777,
            lighthouse: NodeId(crate::random_array()),
            network: NetworkId::random(),
            network_name: "dev".into(),
            token: crate::random_array(),
            extra_lighthouses: vec![crate::control::LighthouseRef {
                host: "lh2.example.com".into(),
                port: 7777,
                key: NodeId(crate::random_array()),
                name: "lh2".into(),
            }],
        };
        let s = inv.encode();
        assert!(s.starts_with("ig1:"));
        assert_eq!(s.parse::<Invite>().unwrap(), inv);
        assert!("nope".parse::<Invite>().is_err());
    }
}
