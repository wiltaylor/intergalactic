//! Abstraction over a TUN device so the engine can run on Linux, Windows,
//! Android and in tests without knowing how packets reach the OS.

use async_trait::async_trait;
use ig_proto::NetworkId;
use std::io;

#[async_trait]
pub trait TunDevice: Send + Sync {
    /// Read one IP packet. Resolves when a packet is available.
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Write one IP packet without blocking. Dropping on back-pressure is fine;
    /// IP is best-effort.
    fn send(&self, pkt: &[u8]) -> io::Result<()>;
    /// Interface name for status output.
    fn name(&self) -> String;
}

/// Which traffic a TUN carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TunScope {
    /// One interface per network (desktop). The engine writes packets for this
    /// network's address to it.
    Network(NetworkId),
    /// One interface for every network (Android `VpnService`, which allows only
    /// one TUN per app). The device carries all overlay addresses.
    All,
}

/// In-memory TUN backed by channels. Used by tests and useful for embedding the
/// engine in a userspace network stack.
pub mod channel {
    use super::TunDevice;
    use async_trait::async_trait;
    use std::io;
    use tokio::sync::mpsc;

    pub struct ChannelTun {
        name: String,
        /// Packets the "OS" sends into the tunnel.
        from_os: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        /// Packets the tunnel delivers to the "OS".
        to_os: mpsc::Sender<Vec<u8>>,
    }

    pub struct OsSide {
        pub to_tun: mpsc::Sender<Vec<u8>>,
        pub from_tun: mpsc::Receiver<Vec<u8>>,
    }

    impl ChannelTun {
        pub fn new(name: &str) -> (ChannelTun, OsSide) {
            let (to_tun, from_os) = mpsc::channel(1024);
            let (to_os, from_tun) = mpsc::channel(1024);
            (
                ChannelTun {
                    name: name.to_string(),
                    from_os: tokio::sync::Mutex::new(from_os),
                    to_os,
                },
                OsSide { to_tun, from_tun },
            )
        }
    }

    #[async_trait]
    impl TunDevice for ChannelTun {
        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut rx = self.from_os.lock().await;
            match rx.recv().await {
                Some(pkt) => {
                    let n = pkt.len().min(buf.len());
                    buf[..n].copy_from_slice(&pkt[..n]);
                    Ok(n)
                }
                None => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "channel tun closed",
                )),
            }
        }

        fn send(&self, pkt: &[u8]) -> io::Result<()> {
            self.to_os
                .try_send(pkt.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "channel tun full"))
        }

        fn name(&self) -> String {
            self.name.clone()
        }
    }
}
