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

/// The nft script that installs exactly `rules`, replacing an earlier set.
///
/// Every DNAT rule carries `fib daddr type local`, so only packets addressed
/// to one of this machine's own addresses are translated. Without the guard,
/// the output chain would also redirect the lighthouse's own connections to
/// unrelated remote servers on the same port, and prerouting would intercept
/// unrelated routed traffic.
pub fn script(rules: &[ForwardRule]) -> String {
    let mut script = String::from(
        "table ip ig_forwards\n\
         delete table ip ig_forwards\n\
         table ip6 ig_forwards\n\
         delete table ip6 ig_forwards\n",
    );
    for family in ["ip", "ip6"] {
        let family_rules = rules
            .iter()
            .filter(|r| (family == "ip6") == r.dst.is_ipv6())
            .map(|r| {
                let dst = if r.dst.is_ipv6() {
                    format!("[{}]:{}", r.dst.ip(), r.dst.port())
                } else {
                    r.dst.to_string()
                };
                (r, dst)
            })
            .collect::<Vec<_>>();
        script.push_str(&format!(
            "table {family} ig_forwards {{\n\
             \tchain pre {{ type nat hook prerouting priority -100; policy accept;\n"
        ));
        for (r, dst) in &family_rules {
            script.push_str(&format!(
                "\t\tiifname != \"ig-*\" fib daddr type local {} dport {} dnat to {}\n",
                r.proto, r.public_port, dst
            ));
        }
        // Locally generated connections (a client on the lighthouse itself) skip
        // prerouting; give them the same translation in the output hook.
        script.push_str("\t}\n\tchain out { type nat hook output priority -100; policy accept;\n");
        for (r, dst) in &family_rules {
            script.push_str(&format!(
                "\t\tfib daddr type local {} dport {} dnat to {}\n",
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
    script
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
    let script = script(rules);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<ForwardRule> {
        vec![
            ForwardRule {
                proto: ForwardProto::Tcp,
                public_port: 443,
                dst: "100.64.0.7:8443".parse().unwrap(),
            },
            ForwardRule {
                proto: ForwardProto::Udp,
                public_port: 5353,
                dst: "100.64.0.7:53".parse().unwrap(),
            },
            ForwardRule {
                proto: ForwardProto::Tcp,
                public_port: 8080,
                dst: "[fd00:ab::7]:80".parse().unwrap(),
            },
            ForwardRule {
                proto: ForwardProto::Udp,
                public_port: 51820,
                dst: "[fd00:ab::7]:51820".parse().unwrap(),
            },
        ]
    }

    fn dnat_lines(script: &str) -> Vec<&str> {
        script
            .lines()
            .map(str::trim)
            .filter(|l| l.contains(" dnat to "))
            .collect()
    }

    #[test]
    fn every_dnat_rule_is_limited_to_local_addresses() {
        let s = script(&sample());
        let lines = dnat_lines(&s);
        // Four forwards, each in a prerouting and an output chain.
        assert_eq!(lines.len(), 8, "{s}");
        for l in &lines {
            assert!(
                l.contains("fib daddr type local"),
                "unguarded dnat rule: {l}\n{s}"
            );
            // The guard must sit in the match part, before the dnat action.
            let (matches, _) = l.split_once(" dnat to ").unwrap();
            assert!(matches.contains("fib daddr type local"), "{l}");
        }
    }

    #[test]
    fn exact_rule_lines_for_both_hooks_and_families() {
        let s = script(&sample());
        let expected = [
            // ip prerouting
            "iifname != \"ig-*\" fib daddr type local tcp dport 443 dnat to 100.64.0.7:8443",
            "iifname != \"ig-*\" fib daddr type local udp dport 5353 dnat to 100.64.0.7:53",
            // ip output
            "fib daddr type local tcp dport 443 dnat to 100.64.0.7:8443",
            "fib daddr type local udp dport 5353 dnat to 100.64.0.7:53",
            // ip6 prerouting
            "iifname != \"ig-*\" fib daddr type local tcp dport 8080 dnat to [fd00:ab::7]:80",
            "iifname != \"ig-*\" fib daddr type local udp dport 51820 dnat to [fd00:ab::7]:51820",
            // ip6 output
            "fib daddr type local tcp dport 8080 dnat to [fd00:ab::7]:80",
            "fib daddr type local udp dport 51820 dnat to [fd00:ab::7]:51820",
        ];
        assert_eq!(dnat_lines(&s), expected, "{s}");
    }

    #[test]
    fn families_are_kept_apart() {
        let s = script(&sample());
        let (ip, ip6) = s.split_once("table ip6 ig_forwards {").unwrap();
        assert!(!ip.contains("fd00:ab::7"), "{s}");
        assert!(!ip6.contains("100.64.0.7"), "{s}");
        assert!(!s.contains("ip ig_forwards {\n\t}"), "{s}");
    }

    #[test]
    fn chain_hooks_and_priorities_are_unchanged() {
        let s = script(&sample());
        assert_eq!(
            s.matches("type nat hook prerouting priority -100;").count(),
            2,
            "{s}"
        );
        assert_eq!(
            s.matches("type nat hook output priority -100;").count(),
            2,
            "{s}"
        );
        assert_eq!(
            s.matches("type nat hook postrouting priority 100;").count(),
            2,
            "{s}"
        );
        assert_eq!(s.matches("oifname \"ig-*\" masquerade").count(), 2, "{s}");
    }

    fn not_permitted(stderr: &str) -> bool {
        stderr.contains("Operation not permitted") || stderr.contains("Permission denied")
    }

    /// Check the script with the real `nft` parser (`nft -c -f`). `nft -c`
    /// needs netlink for its cache, so as a normal user the test retries
    /// inside an unprivileged user+network namespace (`unshare -rn`). Skipped
    /// with a message when `nft` is missing or neither path is permitted.
    #[test]
    fn nft_accepts_the_script() {
        let dir = std::env::temp_dir().join(format!("ig-forward-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ig-forwards.nft");
        std::fs::write(&path, script(&sample())).unwrap();
        let path = path.to_string_lossy().into_owned();
        let direct = Command::new("nft").args(["-c", "-f", &path]).output();
        let direct = match direct {
            Ok(o) => o,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                eprintln!("skipped: cannot run nft: {e}");
                return;
            }
        };
        let direct_err = String::from_utf8_lossy(&direct.stderr).into_owned();
        let out = if direct.status.success() || !not_permitted(&direct_err) {
            direct
        } else {
            match Command::new("unshare")
                .args(["-rn", "nft", "-c", "-f", &path])
                .output()
            {
                Ok(o) => o,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    eprintln!("skipped: nft -c needs CAP_NET_ADMIN and unshare is missing: {e}");
                    return;
                }
            }
        };
        let _ = std::fs::remove_dir_all(&dir);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && not_permitted(&stderr) {
            eprintln!("skipped: nft -c needs CAP_NET_ADMIN: {}", stderr.trim());
            return;
        }
        assert!(
            out.status.success(),
            "nft -c rejected the script:\n{stderr}"
        );
    }
}
