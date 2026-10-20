//! Kernel side of the gateway role. The engine rewrites a device's overlay
//! address to its physical address and hands the packet to the TUN; the kernel
//! must then forward it onto the LAN with source NAT, and route the reply back
//! into the TUN. Linux: sysctl + an nftables masquerade table. Windows: IP
//! forwarding plus a NetNat for the overlay prefix (best effort).

use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> bool {
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            tracing::warn!(cmd, ?args, stderr = %String::from_utf8_lossy(&o.stderr).trim(), "gateway command failed");
            false
        }
        Err(e) => {
            tracing::warn!(cmd, error = %e, "cannot run gateway command");
            false
        }
    }
}

/// Make this host forward and masquerade traffic from the given overlay
/// prefixes, and translate its own traffic to the devices it fronts
/// (`devices` = overlay address -> physical address). The kernel cannot accept
/// a packet from the TUN whose source is the host's own address, so the local
/// case is a plain DNAT in the output hook instead. Idempotent; call with the
/// full current set on every change.
pub fn apply(prefixes: &[Ipv4Net], devices: &[(Ipv4Addr, Ipv4Addr)]) {
    if prefixes.is_empty() {
        remove();
        return;
    }
    if cfg!(target_os = "linux") {
        run("sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"]);
        let mut script = String::from(
            "table ip ig_gateway\n\
             delete table ip ig_gateway\n\
             table ip ig_gateway {\n\
             \tchain post { type nat hook postrouting priority 100; policy accept;\n",
        );
        for p in prefixes {
            script.push_str(&format!(
                "\t\tip saddr {p} oifname != \"ig-*\" masquerade\n"
            ));
        }
        script.push_str("\t}\n\tchain out { type nat hook output priority -100; policy accept;\n");
        for (addr, target) in devices {
            script.push_str(&format!("\t\tip daddr {addr} dnat to {target}\n"));
        }
        script.push_str("\t}\n}\n");
        let path = std::env::temp_dir().join("ig-gateway.nft");
        match std::fs::write(&path, &script) {
            Ok(()) => {
                run("nft", &["-f", path.to_string_lossy().as_ref()]);
            }
            Err(e) => tracing::warn!(error = %e, "cannot write nft script"),
        }
        tracing::info!(?prefixes, "gateway forwarding enabled");
    } else if cfg!(windows) {
        let mut ps = String::from(
            "Get-NetIPInterface -AddressFamily IPv4 | Where-Object InterfaceAlias -like 'ig-*' | Set-NetIPInterface -Forwarding Enabled; \
             Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.ConnectionState -eq 'Connected' } | Set-NetIPInterface -Forwarding Enabled; ",
        );
        for p in prefixes {
            let name = format!("ig-{}", p.to_string().replace(['.', '/'], "-"));
            ps.push_str(&format!(
                "if (-not (Get-NetNat -Name '{name}' -ErrorAction SilentlyContinue)) {{ New-NetNat -Name '{name}' -InternalIPInterfaceAddressPrefix '{p}' | Out-Null }}; "
            ));
        }
        run(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &ps],
        );
        tracing::info!(?prefixes, "gateway forwarding enabled (NetNat)");
    } else {
        tracing::warn!("gateway role is not supported on this platform");
    }
}

/// Undo everything `apply` did.
pub fn remove() {
    if cfg!(target_os = "linux") {
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", "ig_gateway"])
            .output();
    } else if cfg!(windows) {
        run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetNat | Where-Object Name -like 'ig-*' | Remove-NetNat -Confirm:$false",
            ],
        );
    }
}
