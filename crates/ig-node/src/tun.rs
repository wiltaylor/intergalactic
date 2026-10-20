//! Real TUN devices via `tun-rs` (Linux `/dev/net/tun`, Windows Wintun).

use async_trait::async_trait;
use ig_core::TunDevice;
use ig_proto::control::NetworkInfo;
use ig_proto::OVERLAY_MTU;
use std::io;
use tun_rs::{AsyncDevice, DeviceBuilder};

pub struct OsTun {
    dev: AsyncDevice,
    name: String,
}

/// Interface name derived from the network name. Linux allows 15 bytes.
pub fn interface_name(network: &NetworkInfo) -> String {
    let clean: String = network
        .name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let mut name = format!("ig-{clean}");
    if name.len() > 15 {
        name.truncate(15);
    }
    if name.len() <= 3 {
        name = format!("ig-{}", &network.id.to_string()[..8]);
    }
    name
}

/// Pick an interface name that is not already in use on this host. Two
/// networks called `dev` on different lighthouses would otherwise collide.
pub fn free_interface_name(network: &NetworkInfo, taken: &[String]) -> String {
    let base = interface_name(network);
    if !taken.contains(&base) {
        return base;
    }
    for i in 2..100 {
        let suffix = format!("-{i}");
        let mut candidate = base.clone();
        candidate.truncate(15 - suffix.len());
        candidate.push_str(&suffix);
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    base
}

impl OsTun {
    pub fn create(network: &NetworkInfo, taken: &[String]) -> io::Result<OsTun> {
        let name = free_interface_name(network, taken);
        #[allow(unused_mut)]
        let mut builder = DeviceBuilder::new()
            .name(name.clone())
            .ipv4(network.address, network.cidr.prefix_len(), None)
            .mtu(OVERLAY_MTU);
        if let (Some(a6), Some(c6)) = (network.address6, network.cidr6) {
            builder = builder.ipv6(a6, c6.prefix_len());
        }
        #[cfg(windows)]
        {
            // Stable GUID per network keeps Windows from creating a new adapter
            // profile on every start.
            let mut guid = [0u8; 16];
            guid[..8].copy_from_slice(&network.id.0);
            guid[8..].copy_from_slice(b"intergal");
            builder = builder
                .device_guid(u128::from_le_bytes(guid))
                .description("Intergalactic overlay");
        }
        let dev = builder.build_async()?;
        let actual = dev.name().unwrap_or_else(|_| name.clone());
        tracing::info!(
            interface = %actual,
            address = %network.address,
            cidr = %network.cidr,
            address6 = ?network.address6,
            "created tun"
        );
        Ok(OsTun { dev, name: actual })
    }
}

#[async_trait]
impl TunDevice for OsTun {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.recv(buf).await
    }

    fn send(&self, pkt: &[u8]) -> io::Result<()> {
        self.dev.try_send(pkt).map(|_| ())
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
