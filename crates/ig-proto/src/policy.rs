//! Per-network traffic policy.
//!
//! A network with an empty rule list allows everything between members. A network
//! with rules only lets a member *accept* new inbound flows that match a rule.
//! Replies to flows a member opened itself are always allowed (see
//! `ig_core::filter`). This is how an untrusted "game" network can be limited to
//! the game's ports while a "dev" network stays wide open.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Allow-list of inbound flows. Empty means allow all.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Policy {
    pub fn allow_all() -> Self {
        Policy { rules: Vec::new() }
    }

    pub fn is_allow_all(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Relay bandwidth limits for one network, enforced by the lighthouse.
/// Values are kilobits per second; 0 means unlimited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLimit {
    /// Cap for each member's relayed traffic in this network.
    #[serde(default)]
    pub per_node_kbps: u32,
    /// Cap for all relayed traffic of this network together.
    #[serde(default)]
    pub total_kbps: u32,
}

impl RelayLimit {
    pub fn unlimited() -> Self {
        RelayLimit::default()
    }

    pub fn is_unlimited(&self) -> bool {
        self.per_node_kbps == 0 && self.total_kbps == 0
    }
}

impl fmt::Display for RelayLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unlimited() {
            return f.write_str("unlimited");
        }
        let mut parts = Vec::new();
        if self.per_node_kbps > 0 {
            parts.push(format!("{} kbps/node", self.per_node_kbps));
        }
        if self.total_kbps > 0 {
            parts.push(format!("{} kbps total", self.total_kbps));
        }
        f.write_str(&parts.join(", "))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
        })
    }
}

/// `tcp:22,80,8000-8100`, `udp:27015-27030`, `icmp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub proto: Proto,
    /// Inclusive port ranges. Ignored for ICMP. Empty means all ports.
    #[serde(default)]
    pub ports: Vec<(u16, u16)>,
}

impl Rule {
    pub fn matches_port(&self, port: u16) -> bool {
        self.ports.is_empty()
            || self
                .ports
                .iter()
                .any(|(lo, hi)| (*lo..=*hi).contains(&port))
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.proto)?;
        if !self.ports.is_empty() {
            f.write_str(":")?;
            for (i, (lo, hi)) in self.ports.iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }
                if lo == hi {
                    write!(f, "{lo}")?;
                } else {
                    write!(f, "{lo}-{hi}")?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid rule `{0}`: expected `tcp:PORTS`, `udp:PORTS` or `icmp`")]
pub struct ParseRuleError(pub String);

impl FromStr for Rule {
    type Err = ParseRuleError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseRuleError(s.to_string());
        let (proto, ports) = match s.split_once(':') {
            Some((p, ports)) => (p, Some(ports)),
            None => (s, None),
        };
        let proto = match proto.trim().to_ascii_lowercase().as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            "icmp" => Proto::Icmp,
            _ => return Err(err()),
        };
        let mut out = Vec::new();
        if let Some(ports) = ports {
            if proto == Proto::Icmp {
                return Err(err());
            }
            for part in ports.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (lo, hi) = match part.split_once('-') {
                    Some((a, b)) => (
                        a.trim().parse().map_err(|_| err())?,
                        b.trim().parse().map_err(|_| err())?,
                    ),
                    None => {
                        let p: u16 = part.parse().map_err(|_| err())?;
                        (p, p)
                    }
                };
                if lo > hi {
                    return Err(err());
                }
                out.push((lo, hi));
            }
        }
        Ok(Rule { proto, ports: out })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_prints_rules() {
        let r: Rule = "tcp:22,80,8000-8100".parse().unwrap();
        assert_eq!(r.proto, Proto::Tcp);
        assert!(r.matches_port(22));
        assert!(r.matches_port(8050));
        assert!(!r.matches_port(443));
        assert_eq!(r.to_string(), "tcp:22,80,8000-8100");
        let icmp: Rule = "icmp".parse().unwrap();
        assert_eq!(icmp.to_string(), "icmp");
        assert!("icmp:8".parse::<Rule>().is_err());
        assert!("tcp:9-1".parse::<Rule>().is_err());
        assert!("sctp:1".parse::<Rule>().is_err());
    }
}
