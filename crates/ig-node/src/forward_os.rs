//! Kernel side of public port forwards on a lighthouse: DNAT from a public port
//! to an overlay address, with source NAT onto the lighthouse's overlay address
//! so replies come back through the tunnel. Linux nftables only; a lighthouse is
//! a Linux VPS.

use ig_proto::tunnel::ForwardProto;
use std::net::SocketAddr;
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardRule {
    pub proto: ForwardProto,
    pub public_port: u16,
    pub dst: SocketAddr,
}

fn run(cmd: &str, args: &[&str]) -> bool {
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            tracing::warn!(cmd, ?args, stderr = %String::from_utf8_lossy(&o.stderr).trim(), "forward command failed");
            false
        }
        Err(e) => {
            tracing::warn!(cmd, error = %e, "cannot run forward command");
            false
        }
    }
}

/// Install exactly these rules (replacing earlier ones). Idempotent.
pub fn apply(rules: &[ForwardRule]) {
    if !cfg!(target_os = "linux") {
        if !rules.is_empty() {
            tracing::warn!("public forwards need a Linux lighthouse");
        }
        return;
    }
    if rules.is_empty() {
        remove();
        return;
    }
    run("sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"]);
    run("sysctl", &["-q", "-w", "net.ipv6.conf.all.forwarding=1"]);
    let mut script = String::from(
        "table ip ig_forwards\n\
         delete table ip ig_forwards\n\
         table ip6 ig_forwards\n\
         delete table ip6 ig_forwards\n",
    );
    for family in ["ip", "ip6"] {
        script.push_str(&format!(
            "table {family} ig_forwards {{\n\
             \tchain pre {{ type nat hook prerouting priority -100; policy accept;\n"
        ));
        for r in rules {
            let is6 = r.dst.is_ipv6();
            if (family == "ip6") != is6 {
                continue;
            }
            let dst = if is6 {
                format!("[{}]:{}", r.dst.ip(), r.dst.port())
            } else {
                r.dst.to_string()
            };
            script.push_str(&format!(
                "\t\tiifname != \"ig-*\" {} dport {} dnat to {}\n",
                r.proto, r.public_port, dst
            ));
        }
        // Locally generated connections (a client on the lighthouse itself) skip
        // prerouting; give them the same translation in the output hook.
        script.push_str("\t}\n\tchain out { type nat hook output priority -100; policy accept;\n");
        for r in rules {
            let is6 = r.dst.is_ipv6();
            if (family == "ip6") != is6 {
                continue;
            }
            let dst = if is6 {
                format!("[{}]:{}", r.dst.ip(), r.dst.port())
            } else {
                r.dst.to_string()
            };
            script.push_str(&format!(
                "\t\t{} dport {} dnat to {}\n",
                r.proto, r.public_port, dst
            ));
        }
        script.push_str(
            "\t}\n\
             \tchain post { type nat hook postrouting priority 100; policy accept;\n\
             \t\toifname \"ig-*\" masquerade\n\
             \t}\n}\n",
        );
    }
    let path = std::env::temp_dir().join("ig-forwards.nft");
    match std::fs::write(&path, &script) {
        Ok(()) => {
            if run("nft", &["-f", path.to_string_lossy().as_ref()]) {
                tracing::info!(count = rules.len(), "forward rules installed");
            }
        }
        Err(e) => tracing::warn!(error = %e, "cannot write nft script"),
    }
}

pub fn remove() {
    if cfg!(target_os = "linux") {
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", "ig_forwards"])
            .output();
        let _ = Command::new("nft")
            .args(["delete", "table", "ip6", "ig_forwards"])
            .output();
    }
}
