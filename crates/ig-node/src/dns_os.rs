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
use std::net::IpAddr;
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

/// What the OS resolver must know about one overlay interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsPlanEntry {
    pub iface: String,
    /// The engine's DNS responder addresses inside the network.
    pub servers: Vec<IpAddr>,
    /// `<network label>.<dns_domain>`.
    pub zone: String,
    /// Shared suffix, e.g. `ig.internal`.
    pub domain: String,
}

/// The resolver configuration that the current memberships require. Pure:
/// derived from data only, so `reconcile` can compare it with the plan it
/// applied last and touch the OS only when something differs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsPlan {
    /// Sorted by interface name, so equal inputs give equal plans.
    pub entries: Vec<DnsPlanEntry>,
}

impl DnsPlan {
    pub fn new<'a>(ifaces: impl IntoIterator<Item = (&'a str, &'a NetworkInfo)>) -> Self {
        let mut entries: Vec<DnsPlanEntry> = ifaces
            .into_iter()
            .map(|(iface, net)| {
                let mut servers = vec![IpAddr::V4(net.dns_server_v4())];
                servers.extend(net.dns_server_v6().map(IpAddr::V6));
                DnsPlanEntry {
                    iface: iface.to_string(),
                    servers,
                    zone: format!("{}.{}", dns_label(&net.name), net.dns_domain),
                    domain: net.dns_domain.clone(),
                }
            })
            .collect();
        entries.sort_by(|a, b| a.iface.cmp(&b.iface));
        Self { entries }
    }

    /// One server per shared domain suffix: the first interface that serves it.
    pub fn domain_servers(&self) -> Vec<(String, IpAddr)> {
        let mut out: Vec<(String, IpAddr)> = Vec::new();
        for e in &self.entries {
            if !out.iter().any(|(d, _)| *d == e.domain) {
                if let Some(server) = e.servers.first() {
                    out.push((e.domain.clone(), *server));
                }
            }
        }
        out
    }

    fn entry(&self, iface: &str) -> Option<&DnsPlanEntry> {
        self.entries.iter().find(|e| e.iface == iface)
    }
}

/// Bring the OS resolver from `current` (None: unknown, e.g. at start-up) to
/// `next`, then remember `next` as the current plan (System mode only).
///
/// Interfaces whose entry is new or changed get their per-interface settings
/// re-applied. On Windows the NRPT rule set is rebuilt from the whole plan
/// whenever anything differs, so a removed network's server never lingers in a
/// rule, and the shared suffix rule moves to a remaining network.
pub fn apply_plan(mode: DnsMode, current: &mut Option<DnsPlan>, next: DnsPlan) {
    if mode != DnsMode::System {
        return;
    }
    if current.as_ref() == Some(&next) {
        return;
    }
    for e in &next.entries {
        if current.as_ref().and_then(|c| c.entry(&e.iface)) != Some(e) {
            configure_interface(e);
        }
    }
    // Interfaces that left the plan are gone; their settings die with them.
    apply_windows_nrpt(&next);
    *current = Some(next);
}

/// Configure the resolver for one interface/network.
fn configure_interface(e: &DnsPlanEntry) {
    let iface = e.iface.as_str();
    if cfg!(windows) {
        for server in &e.servers {
            let family = match server {
                IpAddr::V4(_) => "ipv4",
                IpAddr::V6(_) => "ipv6",
            };
            run(
                "netsh",
                &[
                    "interface",
                    family,
                    "set",
                    "dnsservers",
                    &format!("name={iface}"),
                    "static",
                    &server.to_string(),
                    "primary",
                    "validate=no",
                ]
                .map(String::from),
            );
        }
        // NRPT rules are rebuilt as a set in `apply_windows_nrpt`.
    } else {
        let mut args = vec!["dns".to_string(), iface.to_string()];
        args.extend(e.servers.iter().map(|s| s.to_string()));
        run("resolvectl", &args);
        run(
            "resolvectl",
            &[
                "domain".into(),
                iface.into(),
                format!("~{}", e.zone),
                format!("~{}", e.domain),
            ],
        );
        // Keep these interfaces out of the default route so unrelated queries
        // never reach the overlay responder.
        let _ = Command::new("resolvectl")
            .args(["default-route", iface, "false"])
            .output();
    }
    tracing::info!(interface = iface, zone = e.zone, "resolver configured");
}

/// Rebuild the Windows NRPT rule set from the plan.
fn apply_windows_nrpt(plan: &DnsPlan) {
    if !cfg!(windows) {
        return;
    }
    run(
        "powershell",
        &[
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            nrpt_script(plan),
        ],
    );
}

/// PowerShell that replaces every rule we own with the rules in `plan`.
fn nrpt_script(plan: &DnsPlan) -> String {
    let mut script = String::from(
        "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'intergalactic' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;",
    );
    for e in &plan.entries {
        let Some(server) = e.servers.first() else {
            continue;
        };
        script.push_str(&format!(
            " Add-DnsClientNrptRule -Namespace '.{}' -NameServers '{server}' -Comment 'intergalactic';",
            e.zone
        ));
    }
    for (domain, server) in plan.domain_servers() {
        script.push_str(&format!(
            " Add-DnsClientNrptRule -Namespace '.{domain}' -NameServers '{server}' -Comment 'intergalactic';"
        ));
    }
    script
}

/// Remove everything we added (Windows NRPT). Linux state dies with the interface.
pub fn cleanup(mode: DnsMode) {
    if mode == DnsMode::System {
        apply_windows_nrpt(&DnsPlan::default());
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

#[cfg(test)]
mod tests {
    use super::*;
    use ig_proto::ids::NetworkId;

    fn net(name: &str, cidr: &str, domain: &str) -> NetworkInfo {
        let cidr: ipnet::Ipv4Net = cidr.parse().unwrap();
        NetworkInfo {
            id: NetworkId::random(),
            name: name.to_string(),
            cidr,
            address: std::net::Ipv4Addr::from(u32::from(cidr.network()) + 7),
            cidr6: None,
            address6: None,
            policy: Default::default(),
            dns_domain: domain.to_string(),
            dns_name: "me".to_string(),
            relay_limit: Default::default(),
            devices: vec![],
            forwards: vec![],
            exposes_allowed: true,
            lighthouses: vec![],
        }
    }

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn leaving_one_network_drops_its_server_and_keeps_the_shared_suffix() {
        let home = net("Home", "100.64.0.0/24", "ig.internal");
        let work = net("Work", "100.65.0.0/24", "ig.internal");
        let both = DnsPlan::new([("ig0", &home), ("ig1", &work)]);
        assert_eq!(
            both.domain_servers(),
            vec![("ig.internal".to_string(), v4("100.64.0.1"))]
        );

        // Leave `Home`: the plan loses ig0 and its server moves out of the
        // shared suffix rule.
        let only_work = DnsPlan::new([("ig1", &work)]);
        assert_ne!(both, only_work);
        assert_eq!(only_work.entries.len(), 1);
        assert_eq!(only_work.entries[0].iface, "ig1");
        assert_eq!(only_work.entries[0].servers, vec![v4("100.65.0.1")]);
        assert_eq!(only_work.entries[0].zone, "work.ig.internal");
        assert_eq!(
            only_work.domain_servers(),
            vec![("ig.internal".to_string(), v4("100.65.0.1"))]
        );

        let script = nrpt_script(&only_work);
        assert!(!script.contains("100.64.0.1"), "{script}");
        assert!(script.contains("-Namespace '.work.ig.internal' -NameServers '100.65.0.1'"));
        assert!(script.contains("-Namespace '.ig.internal' -NameServers '100.65.0.1'"));
        assert!(!script.contains("home.ig.internal"));
        // Exactly one rule per namespace.
        assert_eq!(script.matches("-Namespace '.ig.internal'").count(), 1);
    }

    #[test]
    fn metadata_change_changes_the_plan_and_unchanged_set_does_not() {
        let home = net("Home", "100.64.0.0/24", "ig.internal");
        let work = net("Work", "100.65.0.0/24", "ig.internal");
        let base = DnsPlan::new([("ig0", &home), ("ig1", &work)]);

        // Same memberships in another order: equal plan.
        let reordered = DnsPlan::new([("ig1", &work), ("ig0", &home)]);
        assert_eq!(base, reordered);

        // New domain suffix on one network: the plan changes, and the new
        // suffix gets its own rule served by that network.
        let mut work2 = work.clone();
        work2.dns_domain = "corp.example".to_string();
        let changed = DnsPlan::new([("ig0", &home), ("ig1", &work2)]);
        assert_ne!(base, changed);
        assert_eq!(
            changed.domain_servers(),
            vec![
                ("ig.internal".to_string(), v4("100.64.0.1")),
                ("corp.example".to_string(), v4("100.65.0.1")),
            ]
        );

        // Renamed network: the zone changes.
        let mut work3 = work.clone();
        work3.name = "Office".to_string();
        let renamed = DnsPlan::new([("ig0", &home), ("ig1", &work3)]);
        assert_ne!(base, renamed);
        assert_eq!(renamed.entries[1].zone, "office.ig.internal");

        // This node's own label is not part of the OS resolver configuration.
        let mut home2 = home.clone();
        home2.dns_name = "other".to_string();
        assert_eq!(base, DnsPlan::new([("ig0", &home2), ("ig1", &work)]));
    }

    #[test]
    fn ipv6_prefix_adds_a_v6_server() {
        let mut home = net("Home", "100.64.0.0/24", "ig.internal");
        home.cidr6 = Some("fd00:ab::/64".parse().unwrap());
        let plan = DnsPlan::new([("ig0", &home)]);
        assert_eq!(
            plan.entries[0].servers,
            vec![v4("100.64.0.1"), "fd00:ab::1".parse().unwrap()]
        );
    }

    #[test]
    fn apply_plan_is_a_no_op_outside_system_mode_and_for_equal_plans() {
        let home = net("Home", "100.64.0.0/24", "ig.internal");
        let plan = DnsPlan::new([("ig0", &home)]);
        let mut current = None;
        apply_plan(DnsMode::Off, &mut current, plan.clone());
        assert_eq!(current, None);
        apply_plan(DnsMode::Hosts, &mut current, plan.clone());
        assert_eq!(current, None);
        let mut current = Some(plan.clone());
        apply_plan(DnsMode::System, &mut current, plan.clone());
        assert_eq!(current, Some(plan));
    }
}
