//! Dual-stack UDP helpers shared by nodes and lighthouses.
//!
//! One socket bound to `[::]:port` with `IPV6_V6ONLY=0` carries both IPv4 and
//! IPv6. IPv4 peers then show up as IPv4-mapped IPv6 addresses; [`canonical`]
//! turns those back into plain IPv4 and [`to_wire`] does the reverse for sending.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;

/// Bind a UDP socket. Prefers dual-stack IPv6; falls back to IPv4 only.
/// Returns the socket and whether it is dual-stack.
pub fn bind_dual_stack(ip: IpAddr, port: u16) -> io::Result<(UdpSocket, bool)> {
    if let IpAddr::V6(v6) = ip {
        if let Ok(sock) = bind_v6(v6, port) {
            return Ok((sock, true));
        }
        if !v6.is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("cannot bind [{v6}]:{port}"),
            ));
        }
    }
    let v4 = match ip {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
    };
    let std_sock = std::net::UdpSocket::bind(SocketAddr::from((v4, port)))?;
    std_sock.set_nonblocking(true)?;
    Ok((UdpSocket::from_std(std_sock)?, false))
}

fn bind_v6(ip: Ipv6Addr, port: u16) -> io::Result<UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_only_v6(false)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::from((ip, port)).into())?;
    UdpSocket::from_std(sock.into())
}

/// IPv4-mapped IPv6 address -> IPv4.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// Address to pass to `send_to` on a socket that may be dual-stack.
pub fn to_wire(addr: SocketAddr, dual_stack: bool) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if dual_stack => {
            SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        other => other,
    }
}

/// Can this socket reach `addr` at all? A v4-only socket cannot send to IPv6.
pub fn reachable(addr: SocketAddr, dual_stack: bool) -> bool {
    dual_stack || addr.is_ipv4()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dual_stack_roundtrip_v4_and_v6() {
        let (a, dual) = bind_dual_stack(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap();
        let (b, _) = bind_dual_stack(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap();
        let b_port = b.local_addr().unwrap().port();
        let mut buf = [0u8; 16];
        if dual {
            let v4_target: SocketAddr = format!("127.0.0.1:{b_port}").parse().unwrap();
            a.send_to(b"v4", to_wire(v4_target, dual)).await.unwrap();
            let (n, from) = b.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"v4");
            assert!(canonical(from).is_ipv4(), "{from}");
            let v6_target: SocketAddr = format!("[::1]:{b_port}").parse().unwrap();
            a.send_to(b"v6", to_wire(v6_target, dual)).await.unwrap();
            let (n, from) = b.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"v6");
            assert!(canonical(from).is_ipv6());
        }
    }
}
