//! Desktop node daemon pieces shared by the binary and by tests.

pub mod dns_os;
pub mod firewall;
pub mod gateway_os;
pub mod ipc;
pub mod paths;
pub mod tun;

#[cfg(windows)]
pub mod service;
