// Gateway devices: alpha and bravo offer to forward for a device (the lighthouse
// VM itself, 10.70.0.10, which is on their LAN). win and bravo reach it through
// the active gateway; alpha then drops off the network and bravo takes over.
// Run after linux.ws and windows.ws.
use vmlab

fn sh(m: Machine, cmd: string) -> Result[ExecResult, string] {
    m.exec_timeout("/bin/sh", ["-c", cmd], 180)
}

fn must(lab: Lab, m: Machine, cmd: string) -> Result[string, string] {
    let r = sh(m, cmd)?
    if r.exit_code != 0 {
        return Err(fmt("[{}] `{}` exited {}\nstdout: {}\nstderr: {}", m.name(), cmd, r.exit_code, r.stdout, r.stderr))
    }
    Ok(r.stdout)
}

fn wait_sh(lab: Lab, m: Machine, cmd: string, attempts: int) -> Result[string, string] {
    for i in 0..attempts {
        let r = sh(m, cmd)?
        if r.exit_code == 0 { return Ok(r.stdout) }
        vmlab::sleep_ms(1000)
    }
    Err(fmt("[{}] `{}` never succeeded after {} attempts", m.name(), cmd, attempts))
}

fn ps(m: Machine, cmd: string) -> Result[ExecResult, string] {
    m.exec_timeout("powershell", ["-NoProfile", "-NonInteractive", "-Command", cmd], 300)
}

fn must_ps(lab: Lab, m: Machine, cmd: string) -> Result[string, string] {
    let r = ps(m, cmd)?
    if r.exit_code != 0 {
        return Err(fmt("[win] `{}` exited {}\nstdout: {}\nstderr: {}", cmd, r.exit_code, r.stdout, r.stderr))
    }
    Ok(r.stdout)
}

fn wait_ps(lab: Lab, m: Machine, cmd: string, attempts: int) -> Result[string, string] {
    for i in 0..attempts {
        let r = ps(m, cmd)?
        if r.exit_code == 0 { return Ok(r.stdout) }
        vmlab::sleep_ms(2000)
    }
    Err(fmt("[win] `{}` never succeeded after {} attempts", cmd, attempts))
}

// Restart the daemon with new flags, keeping identity and memberships.
fn restart_node(lab: Lab, m: Machine, flags: string) -> Result[unit, string] {
    must(lab, m, "pkill -x ig-node; sleep 1; RUST_LOG=info setsid nohup ig-node run " + flags + " > /var/log/ig-node.log 2>&1 < /dev/null & sleep 1; test -S /run/intergalactic/node.sock")?
    wait_sh(lab, m, "ig peers | grep -q online", 30)?
    Ok(())
}

fn setup(lab: Lab) -> Result[unit, string] {
    let lh = lab.vm("lh")?
    let alpha = lab.vm("alpha")?
    let bravo = lab.vm("bravo")?
    let win = lab.vm("win")?
    let admin = "ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock "

    lab.log("the device: an HTTP server on the lighthouse VM (10.70.0.10), which is not a member")
    must(lab, lh, "hostnamectl set-hostname lh")?
    must(lab, lh, "test -f /run/http.pid && kill $(cat /run/http.pid); setsid nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory /etc > /var/log/http.log 2>&1 < /dev/null & echo $! > /run/http.pid; sleep 1")?

    // A previous failed run may have left a link down.
    let l1 = sh(alpha, "ip link set enp0s3 up; dhclient -1 enp0s3 2>/dev/null; true")?
    let l2 = sh(bravo, "ip link set enp0s3 up; dhclient -1 enp0s3 2>/dev/null; true")?

    lab.log("alpha and bravo restart with --gateway")
    restart_node(lab, alpha, "--gateway")?
    restart_node(lab, bravo, "--gateway")?

    lab.log("register the device (automatic gateway choice: any capable node on 10.70.0.0/24)")
    let k = sh(lh, admin + "device remove dev lhbox")?
    lab.log(must(lab, lh, admin + "device add dev lhbox 10.70.0.10")?)
    let devs = wait_sh(lab, lh, admin + "device list dev | grep -q 'alpha\\|bravo'", 20)?
    let listing = must(lab, lh, admin + "device list dev")?
    lab.log(listing)
    let active = must(lab, lh, admin + "device list dev | sed -n 2p | tr -s ' ' | cut -d' ' -f6 | tr -d '\\n'")?
    let active_is_alpha = active == "alpha"
    let first = if active_is_alpha { alpha } else { bravo }
    let second = if active_is_alpha { bravo } else { alpha }
    lab.log(fmt("active gateway: {}", first.name()))

    // The device address follows the members: .2 .3 .4 are alpha, bravo, win.
    wait_sh(lab, bravo, "ig status | grep -q lhbox", 20)?
    lab.log(must(lab, bravo, "ig status | grep -A2 DEVICE")?)
    wait_sh(lab, first, "nft list table ip ig_gateway | grep -q masquerade", 20)?
    lab.log(must(lab, first, "nft list table ip ig_gateway; sysctl net.ipv4.ip_forward")?)

    lab.log("second gateway and win reach the device through the active gateway")
    wait_sh(lab, second, "curl -sS --max-time 4 http://lhbox.dev.ig.test:8080/hostname | grep -qx lh", 30)?
    wait_sh(lab, second, "ping -c 1 -W 2 lhbox.dev.ig.test", 10)?
    wait_ps(lab, win, "exit [int](-not (Test-Connection -Count 1 -Quiet lhbox.dev.ig.test))", 15)?
    let body = must_ps(lab, win, "[Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing http://lhbox.dev.ig.test:8080/hostname).Content).Trim()")?
    if body.trim() != "lh" { return Err("win got unexpected body: " + body) }
    lab.log("win fetched /etc/hostname from the device by name -> " + body.trim())
    lab.log(must(lab, first, "conntrack -L 2>/dev/null | grep -c 10.70.0.10 || true")?)

    lab.log(fmt("{} leaves the network silently (link down); the lighthouse must notice and fail over", first.name()))
    let t0 = must(lab, lh, "date +%s")?
    let down = sh(first, "ip link set enp0s3 down")?
    wait_sh(lab, lh, admin + "device list dev | awk 'NR>1 && $6 == \"" + second.name() + "\"' | grep -q .", 90)?
    let t1 = must(lab, lh, "date +%s")?
    lab.log(fmt("failover to {} after {} -> {} s (idle session reaped)", second.name(), t0.trim(), t1.trim()))
    lab.log(must(lab, lh, admin + "device list dev")?)
    wait_ps(lab, win, "exit [int](-not (Test-Connection -Count 1 -Quiet 10.90.0.6))", 30)?
    let body2 = must_ps(lab, win, "[Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing http://lhbox.dev.ig.test:8080/hostname).Content).Trim()")?
    if body2.trim() != "lh" { return Err("win got unexpected body after failover: " + body2) }
    lab.log("win still reaches the device, now through " + second.name())
    // The new gateway reaches its own device locally (hairpin through its TUN).
    must(lab, second, "curl -sS --max-time 4 http://lhbox.dev.ig.test:8080/hostname | grep -qx lh")?

    lab.log(fmt("{} comes back; the device stays reachable (the choice is deterministic across lighthouses)", first.name()))
    let up = sh(first, "ip link set enp0s3 up; sleep 2; dhclient -1 enp0s3 2>/dev/null || true")?
    wait_sh(lab, first, "ig status | grep -q 'lhbox'", 60)?
    wait_sh(lab, lh, admin + "device list dev | sed -n 2p | tr -s ' ' | cut -d' ' -f6 | grep -qE 'alpha|bravo'", 30)?
    lab.log(must(lab, lh, admin + "device list dev")?)
    wait_sh(lab, first, "curl -sS --max-time 4 http://lhbox.dev.ig.test:8080/hostname | grep -qx lh", 30)?
    wait_sh(lab, second, "curl -sS --max-time 4 http://lhbox.dev.ig.test:8080/hostname | grep -qx lh", 30)?
    wait_ps(lab, win, "exit [int](-not (Test-Connection -Count 1 -Quiet lhbox.dev.ig.test))", 15)?
    lab.log("GATEWAY OK")
    Ok(())
}

fn main(lab: Lab) {
    match setup(lab) {
        Ok(_) => lab.log("done"),
        Err(e) => {
            lab.log("FAILED: " + e)
            Err(e).expect("gateway lab failed")
        }
    }
}
