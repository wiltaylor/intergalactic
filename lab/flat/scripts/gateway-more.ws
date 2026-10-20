// Run after gateway.ws. Two more gateway cases on real machines:
//  A. an IPv6 device (the lighthouse VM's ULA address) behind a Linux gateway;
//  B. the Windows node as a gateway (NetNat) for an IPv4 device.
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

    lab.log("A. IPv6 on the LAN: fd70::/64 on lh, alpha and bravo")
    let a1 = sh(lh, "ip addr add fd70::10/64 dev enp0s3")?
    let a2 = sh(alpha, "ip link set enp0s3 up; ip addr add fd70::11/64 dev enp0s3")?
    let a3 = sh(bravo, "ip addr add fd70::12/64 dev enp0s3")?
    wait_sh(lab, alpha, "ping -6 -c 1 -W 2 fd70::10", 15)?
    // Restart so the gateways report the new IPv6 LAN prefix at once.
    restart_node(lab, alpha, "--gateway")?
    restart_node(lab, bravo, "--gateway")?
    must(lab, lh, "test -f /run/http.pid && kill $(cat /run/http.pid); setsid nohup python3 -m http.server 8080 --bind :: --directory /etc > /var/log/http.log 2>&1 < /dev/null & echo $! > /run/http.pid; sleep 1")?

    lab.log("register lhbox again with an IPv6 address")
    let k = sh(lh, admin + "device remove dev lhbox")?
    lab.log(must(lab, lh, admin + "device add dev lhbox 10.70.0.10 --ipv6 fd70::10")?)
    wait_sh(lab, lh, admin + "device list dev | awk 'NR>1 && $8 != \"none\"' | grep -q .", 30)?
    let listing = must(lab, lh, admin + "device list dev")?
    lab.log(listing)
    let active_is_alpha = listing.contains("alpha (")
    let first = if active_is_alpha { alpha } else { bravo }
    let second = if active_is_alpha { bravo } else { alpha }
    wait_sh(lab, first, "nft list table ip6 ig_gateway | grep -q masquerade", 30)?
    lab.log(must(lab, first, "nft list table ip6 ig_gateway")?)

    lab.log("IPv6 device traffic through the Linux gateway")
    wait_sh(lab, second, "curl -sS -6 --max-time 4 'http://[fd42:9a:1::5]:8080/hostname' | grep -qx lh", 30)?
    let q = must(lab, second, "resolvectl query lhbox.dev.ig.test")?
    if !q.contains("fd42:9a:1::5") { return Err("no AAAA for the device: " + q) }
    lab.log(q.trim())
    must(lab, second, "ping -6 -c 2 -W 2 fd42:9a:1::5")?
    must(lab, second, "curl -sS --max-time 4 http://lhbox.dev.ig.test:8080/hostname | grep -qx lh")?
    // The gateway reaches its own IPv6 device through the kernel output DNAT.
    must(lab, first, "curl -sS -6 --max-time 4 'http://[fd42:9a:1::5]:8080/hostname' | grep -qx lh")?
    wait_ps(lab, win, "exit [int](-not (Test-Connection -Count 1 -Quiet 'fd42:9a:1::5'))", 15)?
    let body6 = must_ps(lab, win, "[Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing 'http://[fd42:9a:1::5]:8080/hostname').Content).Trim()")?
    if body6.trim() != "lh" { return Err("win got unexpected body over IPv6: " + body6) }
    lab.log("IPv6 device OK from the other gateway, from the active gateway itself, and from Windows")

    lab.log("B. Windows as a gateway (NetNat)")
    must_ps(lab, win, "C:\\ig\\ig-node.exe service stop; C:\\ig\\ig-node.exe service uninstall; Start-Sleep 2; C:\\ig\\ig-node.exe service install --hostname win --gateway")?
    wait_ps(lab, win, "C:\\ig\\ig.exe status | Out-Null; exit [int](-not $?)", 20)?
    wait_ps(lab, win, "exit [int](-not (C:\\ig\\ig.exe peers | Select-String -Quiet online))", 30)?
    let win_id = must_ps(lab, win, "(C:\\ig\\ig.exe status | Select-String '^node').ToString().Split(' ')[-1].Trim()")?
    lab.log("win node id: " + win_id.trim())
    let k2 = sh(lh, admin + "device remove dev lhwin")?
    lab.log(must(lab, lh, admin + "device add dev lhwin 10.70.0.10 --via " + win_id.trim())?)
    wait_sh(lab, lh, admin + "device list dev | grep lhwin | grep -q 'win ('", 30)?
    lab.log(must(lab, lh, admin + "device list dev")?)
    let nat = wait_ps(lab, win, "exit [int](-not (Get-NetNat | Where-Object Name -like 'ig-*'))", 30)?
    lab.log(must_ps(lab, win, "Get-NetNat | Format-Table -AutoSize Name,InternalIPInterfaceAddressPrefix,Active | Out-String -Width 200; Get-NetIPInterface -AddressFamily IPv4 | Where-Object Forwarding -eq Enabled | Format-Table -AutoSize InterfaceAlias,Forwarding | Out-String -Width 200")?)
    lab.log(must_ps(lab, win, "Get-Content C:\\ProgramData\\Intergalactic\\node\\ig-node.log | Select-String 'gateway' | Select -Last 4 | Out-String -Width 200")?)
    // lhwin is .6 (lhbox is .5). alpha reaches it through win.
    wait_sh(lab, alpha, "curl -sS --max-time 4 http://lhwin.dev.ig.test:8080/hostname | grep -qx lh", 40)?
    must(lab, alpha, "ping -c 2 -W 2 lhwin.dev.ig.test")?
    lab.log("alpha reached the device through the Windows gateway")
    lab.log("GATEWAY-MORE OK")
    Ok(())
}

fn main(lab: Lab) {
    match setup(lab) {
        Ok(_) => lab.log("done"),
        Err(e) => {
            lab.log("FAILED: " + e)
            Err(e).expect("gateway-more lab failed")
        }
    }
}
