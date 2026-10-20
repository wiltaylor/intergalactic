//! Control channel messages (node <-> lighthouse) carried inside the Noise
//! transport described in [`crate::noise`]. Encoded with postcard.

use crate::{NetworkId, NodeId, Policy, RelayLimit};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Payload of the first Noise handshake message (node -> lighthouse).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u16,
    pub hostname: String,
    /// Free-form OS tag ("linux", "windows", "android").
    pub os: String,
    /// The node is willing to act as a gateway for registered devices on the
    /// LANs it is attached to (`ig-node run --gateway`).
    #[serde(default)]
    pub gateway: bool,
    /// This connection comes from another lighthouse that replicates our store
    /// (see [`crate::replication`]). Its static key must be a registered replica.
    #[serde(default)]
    pub replica: bool,
}

/// Payload of the second Noise handshake message (lighthouse -> node).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u16,
    /// Secret shared for the lifetime of this control session. Authenticates the
    /// node's UDP disco probes so nobody can poison its reflexive address.
    pub session_token: [u8; 32],
    /// Unix time in seconds on the lighthouse, for clock-skew diagnostics only.
    pub server_time: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ToLighthouse {
    /// Join a network using an invite token. The lighthouse replies with
    /// `Joined` or `JoinFailed` carrying the same network id.
    Join {
        network: NetworkId,
        token: [u8; 16],
    },
    /// Leave a network. Membership and address are released.
    Leave {
        network: NetworkId,
    },
    /// Ask for the state of every network this node is already a member of.
    /// Sent once after every (re)connect.
    Resume,
    /// Local candidate endpoints (LAN addresses + UDP port). The lighthouse adds
    /// the reflexive address it observes on UDP and shares the union with peers.
    /// `subnets` are the IPv4 prefixes of the LANs this node sits on; the
    /// lighthouse uses them to pick gateways for registered devices.
    Endpoints {
        local: Vec<SocketAddr>,
        #[serde(default)]
        subnets: Vec<Ipv4Net>,
        #[serde(default)]
        subnets6: Vec<Ipv6Net>,
    },
    /// Ask the lighthouse to tell `target` to start sending towards us so both
    /// NATs open at the same time.
    Punch {
        network: NetworkId,
        target: NodeId,
    },
    Ping {
        nonce: u64,
    },
    /// Ask the lighthouse this message reaches for an ephemeral port forward on
    /// its public address. `public_port = None` lets it pick one from its range.
    /// Answered with `Exposed` or `ExposeFailed`.
    Expose {
        network: NetworkId,
        proto: crate::tunnel::ForwardProto,
        public_port: Option<u16>,
        target: String,
        label: String,
    },
    Unexpose {
        id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FromLighthouse {
    Exposed {
        forward: crate::tunnel::ForwardInfo,
    },
    ExposeFailed {
        target: String,
        reason: String,
    },
    Unexposed {
        id: String,
    },
    Joined {
        network: NetworkInfo,
    },
    JoinFailed {
        network: NetworkId,
        reason: String,
    },
    Left {
        network: NetworkId,
    },
    /// Full membership of one network. Sent after join/resume and whenever
    /// anything about the network or its members changes.
    NetworkState {
        network: NetworkInfo,
        peers: Vec<PeerInfo>,
    },
    /// The node was removed from the network by an admin or the network was deleted.
    Removed {
        network: NetworkId,
        reason: String,
    },
    /// A peer wants to reach us; start sending towards its endpoints now.
    PunchRequest {
        network: NetworkId,
        from: NodeId,
        endpoints: Vec<SocketAddr>,
    },
    Pong {
        nonce: u64,
    },
    Error {
        message: String,
    },
}

/// What a member knows about a network it belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub id: NetworkId,
    pub name: String,
    pub cidr: Ipv4Net,
    /// This node's address inside `cidr`.
    pub address: Ipv4Addr,
    /// Optional IPv6 prefix and this node's address inside it.
    #[serde(default)]
    pub cidr6: Option<Ipv6Net>,
    #[serde(default)]
    pub address6: Option<Ipv6Addr>,
    pub policy: Policy,
    /// DNS suffix for peer names, e.g. `ig.internal`. Names are
    /// `<dns_name>.<network name>.<dns_domain>`.
    #[serde(default)]
    pub dns_domain: String,
    /// This node's own DNS label in the network.
    #[serde(default)]
    pub dns_name: String,
    #[serde(default)]
    pub relay_limit: RelayLimit,
    /// Devices registered in this network and who currently gateways them.
    #[serde(default)]
    pub devices: Vec<DeviceInfo>,
    /// Port forwards on the lighthouse that point at the recipient node.
    #[serde(default)]
    pub forwards: Vec<crate::tunnel::ForwardInfo>,
    /// Whether members may request ephemeral forwards in this network.
    #[serde(default = "default_true")]
    pub exposes_allowed: bool,
    /// Every lighthouse serving this network (primary first). Nodes keep a
    /// control session with each of them.
    #[serde(default)]
    pub lighthouses: Vec<LighthouseRef>,
}

/// How to reach a lighthouse and which key to expect from it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LighthouseRef {
    pub host: String,
    pub port: u16,
    pub key: NodeId,
    /// Human name, e.g. `lh-eu`.
    #[serde(default)]
    pub name: String,
}

fn default_true() -> bool {
    true
}

/// A device on a physical LAN that members reach through a gateway node. The
/// gateway translates `address` (overlay) to `target` (physical) and back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    /// DNS label, unique in the network among members and devices.
    pub dns_name: String,
    /// Overlay address members use.
    pub address: Ipv4Addr,
    /// Physical address on the gateway's LAN.
    pub target: Ipv4Addr,
    /// IPv6 pair, when the network has an IPv6 prefix and the device has an IPv6 address.
    #[serde(default)]
    pub address6: Option<Ipv6Addr>,
    #[serde(default)]
    pub target6: Option<Ipv6Addr>,
    /// Node currently forwarding for this device, if any is online and able.
    pub gateway: Option<NodeId>,
}

impl DeviceInfo {
    /// Overlay addresses of the device.
    pub fn addresses(&self) -> Vec<IpAddr> {
        let mut v = vec![IpAddr::V4(self.address)];
        if let Some(a6) = self.address6 {
            v.push(IpAddr::V6(a6));
        }
        v
    }

    /// Physical address for an overlay address of this device, if it is one.
    pub fn target_for(&self, overlay: &IpAddr) -> Option<IpAddr> {
        match overlay {
            IpAddr::V4(a) if *a == self.address => Some(IpAddr::V4(self.target)),
            IpAddr::V6(a) if Some(*a) == self.address6 => self.target6.map(IpAddr::V6),
            _ => None,
        }
    }

    /// Overlay address for a physical address of this device, if it is one.
    pub fn overlay_for(&self, physical: &IpAddr) -> Option<IpAddr> {
        match physical {
            IpAddr::V4(a) if *a == self.target => Some(IpAddr::V4(self.address)),
            IpAddr::V6(a) if Some(*a) == self.target6 => self.address6.map(IpAddr::V6),
            _ => None,
        }
    }
}

impl NetworkInfo {
    /// Devices this node must gateway.
    pub fn my_devices(&self, me: &NodeId) -> Vec<&DeviceInfo> {
        self.devices
            .iter()
            .filter(|d| d.gateway == Some(*me))
            .collect()
    }

    /// Devices a given peer gateways.
    pub fn devices_via(&self, peer: &NodeId) -> Vec<&DeviceInfo> {
        self.devices
            .iter()
            .filter(|d| d.gateway == Some(*peer))
            .collect()
    }

    /// Address of the in-engine DNS responder: the first host of the prefix.
    /// It is never assigned to a member.
    pub fn dns_server_v4(&self) -> Ipv4Addr {
        dns_server_v4(&self.cidr)
    }

    pub fn dns_server_v6(&self) -> Option<Ipv6Addr> {
        self.cidr6.as_ref().map(dns_server_v6)
    }

    /// All addresses of this node in the network.
    pub fn addresses(&self) -> Vec<IpAddr> {
        let mut v = vec![IpAddr::V4(self.address)];
        if let Some(a6) = self.address6 {
            v.push(IpAddr::V6(a6));
        }
        v
    }

    /// Fully qualified name of this node in the network, without trailing dot.
    pub fn fqdn(&self) -> String {
        format!(
            "{}.{}.{}",
            self.dns_name,
            dns_label(&self.name),
            self.dns_domain
        )
    }
}

pub fn dns_server_v4(cidr: &Ipv4Net) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(cidr.network()) + 1)
}

pub fn dns_server_v6(cidr: &Ipv6Net) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(cidr.network()) + 1)
}

/// Turn a free-form name into a DNS label: lowercase, `[a-z0-9-]`, max 63 chars.
pub fn dns_label(name: &str) -> String {
    let mut out = String::new();
    let mut last_dash = true;
    for c in name.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
        if out.len() >= 63 {
            break;
        }
    }
    let trimmed = out.trim_end_matches('-').to_string();
    if trimmed.is_empty() {
        "node".into()
    } else {
        trimmed
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node: NodeId,
    pub hostname: String,
    /// Unique DNS label of the peer within the network.
    #[serde(default)]
    pub dns_name: String,
    pub address: Ipv4Addr,
    #[serde(default)]
    pub address6: Option<Ipv6Addr>,
    /// Candidate endpoints: LAN addresses as reported by the peer plus the public
    /// address the lighthouse observed. Try all; keep the one that answers.
    pub endpoints: Vec<SocketAddr>,
    /// True while the peer holds a control session with the lighthouse.
    pub online: bool,
}

impl PeerInfo {
    pub fn addresses(&self) -> Vec<IpAddr> {
        let mut v = vec![IpAddr::V4(self.address)];
        if let Some(a6) = self.address6 {
            v.push(IpAddr::V6(a6));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_sanitised() {
        assert_eq!(dns_label("Wil's Laptop"), "wil-s-laptop");
        assert_eq!(dns_label("---"), "node");
        assert_eq!(dns_label("DESKTOP_01"), "desktop-01");
        assert_eq!(
            dns_server_v4(&"10.90.0.0/24".parse().unwrap()),
            Ipv4Addr::new(10, 90, 0, 1)
        );
        assert_eq!(
            dns_server_v6(&"fd00::/64".parse().unwrap()),
            "fd00::1".parse::<Ipv6Addr>().unwrap()
        );
    }
}
