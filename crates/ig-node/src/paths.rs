//! Default file locations per platform.

use std::path::PathBuf;

pub fn default_state_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\Intergalactic\node")
    } else {
        PathBuf::from("/var/lib/intergalactic/node")
    }
}

pub fn default_socket() -> PathBuf {
    if cfg!(windows) {
        // Interpreted as a named-pipe name, see `ipc::socket_name`.
        PathBuf::from("ig-node")
    } else {
        PathBuf::from("/run/intergalactic/node.sock")
    }
}

pub fn os_tag() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unix"
    }
}
