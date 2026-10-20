//! Point the operating system's resolver at the engine's DNS responder for the
//! overlay domains. Only queries for `<network>.<domain>` and `<domain>` are
//! routed there; everything else keeps using the normal resolvers.
//!
//! * Linux: `resolvectl` (systemd-resolved) per interface. Falls back to a
//!   managed block in `/etc/hosts` when resolvectl is not available.
//! * Windows: per-interface DNS server via `netsh` plus Name Resolution Policy
//!   Table rules via PowerShell, so only our suffixes go to the overlay.

use ig_proto::control::{dns_label, NetworkInfo};
use ig_proto::ipc::StatusReport;
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum DnsMode {
    /// Pick the best method for this platform.
    Auto,
    /// systemd-resolved (Linux) or NRPT (Windows).
    System,
    /// Write peers into the hosts file.
    Hosts,
    /// Do not touch the OS resolver.
    Off,
}

fn run(cmd: &str, args: &[String]) -> bool {
    match Command::new(cmd).args(args).output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            tracing::warn!(cmd, ?args, stderr = %String::from_utf8_lossy(&out.stderr).trim(), "command failed");
            false
        }
        Err(e) => {
            tracing::warn!(cmd, error = %e, "cannot run command");
            false
        }
    }
}

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Effective mode after resolving `Auto`.
pub fn resolve_mode(mode: DnsMode) -> DnsMode {
    match mode {
        DnsMode::Auto => {
            if cfg!(windows) || have("resolvectl") {
                DnsMode::System
            } else {
                DnsMode::Hosts
            }
        }
        m => m,
    }
}

/// Configure the resolver for one interface/network (System mode).
pub fn configure_interface(mode: DnsMode, iface: &str, net: &NetworkInfo) {
    if mode != DnsMode::System {
        return;
    }
    let v4 = net.dns_server_v4().to_string();
    let v6 = net.dns_server_v6().map(|a| a.to_string());
    let zone = format!("{}.{}", dns_label(&net.name), net.dns_domain);
    if cfg!(windows) {
        run(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &format!("name={iface}"),
                "static",
                &v4,
                "primary",
                "validate=no",
            ]
            .map(String::from),
        );
        if let Some(v6) = &v6 {
            run(
                "netsh",
                &[
                    "interface",
                    "ipv6",
                    "set",
                    "dnsservers",
                    &format!("name={iface}"),
                    "static",
                    v6,
                    "primary",
                    "validate=no",
                ]
                .map(String::from),
            );
        }
        // NRPT rules are rebuilt as a set in `apply_windows_nrpt`.
    } else {
        let mut servers = vec![v4];
        servers.extend(v6);
        let mut args = vec!["dns".to_string(), iface.to_string()];
        args.extend(servers);
        run("resolvectl", &args);
        run(
            "resolvectl",
            &[
                "domain".into(),
                iface.into(),
                format!("~{zone}"),
                format!("~{}", net.dns_domain),
            ],
        );
        // Keep these interfaces out of the default route so unrelated queries
        // never reach the overlay responder.
        let _ = Command::new("resolvectl")
            .args(["default-route", iface, "false"])
            .output();
    }
    tracing::info!(interface = iface, zone, "resolver configured");
}

/// Rebuild the Windows NRPT rule set for all current networks.
pub fn apply_windows_nrpt(mode: DnsMode, networks: &[NetworkInfo]) {
    if mode != DnsMode::System || !cfg!(windows) {
        return;
    }
    let mut script = String::from(
        "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'intergalactic' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;",
    );
    let mut domains_done = std::collections::HashSet::new();
    for n in networks {
        let server = n.dns_server_v4();
        let zone = format!(".{}.{}", dns_label(&n.name), n.dns_domain);
        script.push_str(&format!(
            " Add-DnsClientNrptRule -Namespace '{zone}' -NameServers '{server}' -Comment 'intergalactic';"
        ));
        if domains_done.insert(n.dns_domain.clone()) {
            script.push_str(&format!(
                " Add-DnsClientNrptRule -Namespace '.{}' -NameServers '{server}' -Comment 'intergalactic';",
                n.dns_domain
            ));
        }
    }
    run(
        "powershell",
        &[
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            script,
        ],
    );
}

/// Remove everything we added (Windows NRPT). Linux state dies with the interface.
pub fn cleanup(mode: DnsMode) {
    if mode == DnsMode::System && cfg!(windows) {
        apply_windows_nrpt(mode, &[]);
    }
    if mode == DnsMode::Hosts {
        let _ = write_hosts_block("");
    }
}

const HOSTS_BEGIN: &str = "# intergalactic begin (managed, do not edit)";
const HOSTS_END: &str = "# intergalactic end";

fn hosts_path() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\System32\drivers\etc\hosts"
    } else {
        "/etc/hosts"
    }
}

/// Hosts-file mode: rewrite our block from the current status.
pub fn apply_hosts(mode: DnsMode, status: &StatusReport) {
    if mode != DnsMode::Hosts {
        return;
    }
    let mut block = String::new();
    for n in &status.networks {
        let fqdn = n.info.fqdn();
        for a in n.info.addresses() {
            block.push_str(&format!(
                "{a}\t{fqdn} {}.{}\n",
                n.info.dns_name, n.info.dns_domain
            ));
        }
    }
    for p in &status.peers {
        for (net, name) in &p.names {
            for (anet, addr) in &p.addresses {
                if anet == net {
                    let short = name.splitn(3, '.').collect::<Vec<_>>();
                    let short_name = if short.len() == 3 {
                        format!("{}.{}", short[0], short[2])
                    } else {
                        name.clone()
                    };
                    block.push_str(&format!("{addr}\t{name} {short_name}\n"));
                }
            }
        }
    }
    if let Err(e) = write_hosts_block(&block) {
        tracing::warn!(error = %e, path = hosts_path(), "cannot update hosts file");
    }
}

fn write_hosts_block(block: &str) -> std::io::Result<()> {
    let path = hosts_path();
    let current = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = String::new();
    let mut skipping = false;
    for line in current.lines() {
        if line.trim() == HOSTS_BEGIN {
            skipping = true;
            continue;
        }
        if line.trim() == HOSTS_END {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !block.is_empty() {
        out.push_str(HOSTS_BEGIN);
        out.push('\n');
        out.push_str(block);
        out.push_str(HOSTS_END);
        out.push('\n');
    }
    if out != current {
        std::fs::write(path, out)?;
    }
    Ok(())
}
