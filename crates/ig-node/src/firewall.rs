//! Windows Defender Firewall treats a new adapter as a Public network and
//! drops unsolicited inbound traffic on it, including ping. The overlay has its
//! own access control (network policies), so each overlay interface gets one
//! inbound allow rule, scoped to that interface, for as long as it exists.
//! Linux needs nothing here: a fresh TUN has no firewall of its own.

use std::process::Command;

fn powershell(script: &str) {
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
    {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::warn!(stderr = %String::from_utf8_lossy(&out.stderr).trim(), "firewall command failed")
        }
        Err(e) => tracing::warn!(error = %e, "cannot run powershell"),
    }
}

fn rule_name(iface: &str) -> String {
    format!("Intergalactic {iface}")
}

/// Allow inbound traffic on one overlay interface.
pub fn allow_interface(iface: &str) {
    if !cfg!(windows) {
        return;
    }
    let name = rule_name(iface);
    powershell(&format!(
        "Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue; \
         New-NetFirewallRule -DisplayName '{name}' -Group 'Intergalactic' -Direction Inbound -Action Allow \
         -InterfaceAlias '{iface}' -Profile Any | Out-Null"
    ));
    tracing::info!(interface = iface, "firewall rule added");
}

/// Remove the rule for one interface.
pub fn remove_interface(iface: &str) {
    if !cfg!(windows) {
        return;
    }
    let name = rule_name(iface);
    powershell(&format!(
        "Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue"
    ));
}

/// Remove every rule this daemon ever added (shutdown or uninstall).
pub fn remove_all() {
    if !cfg!(windows) {
        return;
    }
    powershell("Remove-NetFirewallRule -Group 'Intergalactic' -ErrorAction SilentlyContinue");
}
