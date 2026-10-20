// Windows node: install as a service, join, resolve and reach peers.
use vmlab

fn sh(m: Machine, cmd: string) -> Result[ExecResult, string] {
    m.exec_timeout("/bin/sh", ["-c", cmd], 180)
}

// Run a shell command and fail the script unless it exits 0.
fn must(lab: Lab, m: Machine, cmd: string) -> Result[string, string] {
    let r = sh(m, cmd)?
    if r.exit_code != 0 {
        return Err(fmt("[{}] `{}` exited {}\nstdout: {}\nstderr: {}", m.name(), cmd, r.exit_code, r.stdout, r.stderr))
    }
    Ok(r.stdout)
}

// Run a shell command that must NOT succeed (policy tests).
fn must_fail(lab: Lab, m: Machine, cmd: string) -> Result[unit, string] {
    let r = sh(m, cmd)?
    if r.exit_code == 0 {
        return Err(fmt("[{}] `{}` succeeded but should have been blocked\nstdout: {}", m.name(), cmd, r.stdout))
    }
    Ok(())
}

// Poll a shell command until it exits 0 or the attempts run out.
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

fn setup(lab: Lab) -> Result[unit, string] {
    let win = lab.vm("win")?
    let lh = lab.vm("lh")?
    let alpha = lab.vm("alpha")?
    win.wait_ready(1200)?
    let dev_inv = must(lab, lh, "cat /root/invite-dev.txt")?

    lab.log("copying binaries and wintun.dll")
    must_ps(lab, win, "New-Item -ItemType Directory -Force -Path C:\\ig | Out-Null")?
    // A previous run may have left the service running on the old binary.
    let stop = ps(win, "Stop-Service ig-node -ErrorAction SilentlyContinue; Start-Sleep 2; sc.exe delete ig-node; Remove-Item -Recurse -Force C:\\ProgramData\\Intergalactic -ErrorAction SilentlyContinue; exit 0")?
    wait_ps(lab, win, "exit [int]($null -ne (Get-Process ig-node -ErrorAction SilentlyContinue))", 30)?
    win.copy_to("../../bin/ig-node.exe", "C:\\ig\\ig-node.exe")?
    win.copy_to("../../bin/ig.exe", "C:\\ig\\ig.exe")?
    win.copy_to("../../bin/wintun.dll", "C:\\ig\\wintun.dll")?

    lab.log("installing the Windows service")
    // Machine-wide RUST_LOG so the service logs at debug level for diagnosis.
    must_ps(lab, win, "[Environment]::SetEnvironmentVariable('RUST_LOG', 'debug', 'Machine')")?
    let r = ps(win, "C:\\ig\\ig-node.exe service uninstall 2>$null; Start-Sleep 1; C:\\ig\\ig-node.exe service install --hostname win")?
    lab.log(r.stdout + r.stderr)
    if r.exit_code != 0 { return Err("service install failed") }
    let svc = wait_ps(lab, win, "(Get-Service ig-node).Status; exit [int]((Get-Service ig-node).Status -ne 'Running')", 15)?
    lab.log("service state: " + svc.trim())
    let sc = must_ps(lab, win, "(Get-CimInstance Win32_Service -Filter \"Name='ig-node'\").PathName")?
    lab.log("service command line: " + sc.trim())

    lab.log("waiting for the control pipe")
    wait_ps(lab, win, "C:\\ig\\ig.exe status | Out-Null; exit [int](-not $?)", 20)?
    lab.log("joining dev")
    let j = must_ps(lab, win, "C:\\ig\\ig.exe join " + dev_inv.trim())?
    lab.log(j.trim())
    let st = wait_ps(lab, win, "exit [int](-not (C:\\ig\\ig.exe peers | Select-String -Quiet online))", 30)?
    lab.log(must_ps(lab, win, "C:\\ig\\ig.exe status")?)
    let ifs = must_ps(lab, win, "Get-NetIPAddress -InterfaceAlias ig-dev | Format-Table -AutoSize InterfaceAlias,IPAddress,PrefixLength | Out-String -Width 200")?
    lab.log(ifs)

    lab.log("traffic from Windows to alpha (10.90.0.2)")
    wait_ps(lab, win, "exit [int](-not (Test-Connection -Count 1 -Quiet 10.90.0.2))", 20)?
    must_ps(lab, win, "exit [int](-not (Test-Connection -Count 2 -Quiet 'fd42:9a:1::2'))")?
    lab.log("IPv4 and IPv6 ping to alpha OK")

    lab.log("DNS through NRPT")
    let nrpt = must_ps(lab, win, "Get-DnsClientNrptRule | Where-Object Comment -eq intergalactic | Format-Table -AutoSize Namespace,NameServers | Out-String -Width 200")?
    lab.log(nrpt)
    let dns = must_ps(lab, win, "(Resolve-DnsName alpha.dev.ig.test -Type A).IPAddress")?
    lab.log("alpha.dev.ig.test -> " + dns.trim())
    if !dns.contains("10.90.0.2") { return Err("Windows did not resolve alpha.dev.ig.test: " + dns) }
    must_ps(lab, win, "exit [int](-not (Test-Connection -Count 1 -Quiet alpha.dev.ig.test))")?

    lab.log("traffic from alpha to Windows (10.90.0.4) and by name")
    must(lab, alpha, "ping -c 2 -W 3 10.90.0.4")?
    let q = must(lab, alpha, "resolvectl query win.dev.ig.test")?
    lab.log(q.trim())
    must(lab, alpha, "ping -c 2 -W 3 win.dev.ig.test")?
    let peers = must(lab, alpha, "ig peers")?
    lab.log("alpha peers:\n" + peers)

    lab.log("service log tail")
    lab.log(must_ps(lab, win, "Get-Content C:\\ProgramData\\Intergalactic\\node\\ig-node.log -Tail 8 | Out-String -Width 200")?)

    lab.log("stop/start the service and confirm it comes back")
    must_ps(lab, win, "C:\\ig\\ig-node.exe service stop; Start-Sleep 2; C:\\ig\\ig-node.exe service start")?
    wait_ps(lab, win, "exit [int](-not (C:\\ig\\ig.exe peers | Select-String -Quiet online))", 30)?
    let t0 = must(lab, alpha, "date +%s")?
    wait_sh(lab, alpha, "ping -c 1 -W 2 10.90.0.4", 30)?
    let t1 = must(lab, alpha, "date +%s")?
    lab.log(fmt("alpha reached the restarted Windows node after about {}..{} s", t0.trim(), t1.trim()))
    lab.log("WINDOWS OK")
    Ok(())
}

fn main(lab: Lab) {
    match setup(lab) {
        Ok(_) => lab.log("done"),
        Err(e) => {
            lab.log("FAILED: " + e)
            Err(e).expect("windows lab failed")
        }
    }
}
