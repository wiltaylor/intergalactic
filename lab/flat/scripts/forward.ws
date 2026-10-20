// Public port forwards through the lighthouse, carried over the overlay. Run
// after linux.ws and windows.ws. "External" clients are the lighthouse VM's own
// public address and the Windows VM reaching that address over the LAN.
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

fn must_fail(lab: Lab, m: Machine, cmd: string) -> Result[unit, string] {
    let r = sh(m, cmd)?
    if r.exit_code == 0 {
        return Err(fmt("[{}] `{}` succeeded but should have failed\nstdout: {}", m.name(), cmd, r.stdout))
    }
    Ok(())
}

fn wait_sh(lab: Lab, m: Machine, cmd: string, attempts: int) -> Result[string, string] {
    for i in 0..attempts {
        let r = sh(m, cmd)?
        if r.exit_code == 0 { return Ok(r.stdout) }
        vmlab::sleep_ms(1000)
    }
    Err(fmt("[{}] `{}` never succeeded after {} attempts", m.name(), cmd, attempts))
}

fn must_ps(lab: Lab, m: Machine, cmd: string) -> Result[string, string] {
    let r = m.exec_timeout("powershell", ["-NoProfile", "-NonInteractive", "-Command", cmd], 300)?
    if r.exit_code != 0 {
        return Err(fmt("[win] `{}` exited {}\nstdout: {}\nstderr: {}", cmd, r.exit_code, r.stdout, r.stderr))
    }
    Ok(r.stdout)
}

fn setup(lab: Lab) -> Result[unit, string] {
    let lh = lab.vm("lh")?
    let alpha = lab.vm("alpha")?
    let bravo = lab.vm("bravo")?
    let win = lab.vm("win")?
    let admin = "ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock "
    let clean = sh(lh, "for id in $(" + admin + "forward list | sed -n '2,$p' | cut -d' ' -f1); do " + admin + "forward remove $id; done; true")?
    let allow = sh(lh, admin + "network expose game")?

    lab.log("the lighthouse is a member: it has an overlay address and a TUN")
    lab.log(must(lab, lh, admin + "info; ip -br addr show ig-dev")?)
    must(lab, alpha, "ping -c 2 -W 2 lh.dev.ig.test")?
    lab.log("alpha pinged lh.dev.ig.test over the overlay")

    lab.log("alpha serves HTTP on 8080 and UDP echo on 9999 on all addresses")
    must(lab, alpha, "test -f /run/http.pid && kill $(cat /run/http.pid); setsid nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory /etc > /var/log/http.log 2>&1 < /dev/null & echo $! > /run/http.pid; sleep 1")?
    alpha.copy_to("udp-echo.py", "/root/udp-echo.py")?
    must(lab, alpha, "test -f /run/udp.pid && kill $(cat /run/udp.pid); setsid nohup python3 /root/udp-echo.py 9999 > /var/log/udp.log 2>&1 < /dev/null & echo $! > /run/udp.pid; sleep 1")?
    lh.copy_to("udp-send.py", "/root/udp-send.py")?

    lab.log("ephemeral TCP forward: `ig expose 8080` on alpha")
    let out = must(lab, alpha, "ig expose 8080 --label demo | tee /tmp/expose.out")?
    lab.log(out.trim())
    let port = must(lab, alpha, "head -1 /tmp/expose.out | sed -E 's#^tcp://[^ ]*:([0-9]+)  ->.*#\\1#' | tr -d '\\n'")?
    if port == "" { return Err("could not read the public port from `ig expose`") }
    wait_sh(lab, alpha, "ig exposes | grep -q ephemeral", 20)?
    lab.log(must(lab, lh, admin + "forward list; nft list table ip ig_forwards")?)

    lab.log("an outside client fetches through the lighthouse's public address")
    let body = wait_sh(lab, lh, "curl -sS --max-time 4 http://10.70.0.10:" + port + "/hostname | grep -x alpha", 30)?
    lab.log("GET via 10.70.0.10:" + port + " -> " + body.trim())
    let wbody = must_ps(lab, win, "[Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing http://10.70.0.10:" + port + "/hostname).Content).Trim()")?
    if wbody.trim() != "alpha" { return Err("win got: " + wbody) }
    lab.log("win -> " + wbody.trim())
    must(lab, alpha, "dd if=/dev/urandom of=/etc/ig-big.bin bs=1M count=20 2>/dev/null; sha256sum /etc/ig-big.bin | cut -d' ' -f1 > /tmp/big.sum")?
    let want = must(lab, alpha, "cat /tmp/big.sum")?
    let got = must(lab, lh, "curl -sS --max-time 60 http://10.70.0.10:" + port + "/ig-big.bin | sha256sum | cut -d' ' -f1")?
    if got.trim() != want.trim() { return Err("checksum mismatch over the forward") }
    lab.log("20 MiB fetched with matching checksum")
    lab.log(must(lab, lh, "conntrack -L 2>/dev/null | grep -c dport=" + port + " || true")?)

    lab.log("ephemeral UDP forward with a chosen public port")
    lab.log(must(lab, alpha, "ig expose 9999 --udp --public-port 20500")?.trim())
    let echo = wait_sh(lab, lh, "python3 /root/udp-send.py 10.70.0.10 20500 'udp through lighthouse' | grep -x 'udp through lighthouse'", 20)?
    lab.log("UDP echo -> " + echo.trim())

    lab.log("permanent forward by the admin, for bravo's SSH port")
    let bravo_id = must(lab, bravo, "ig status | sed -nE 's/^node +//p' | tr -d ' \\n'")?
    lab.log(must(lab, lh, admin + "forward add dev " + bravo_id + " 20022 self:22 --label ssh")?)
    wait_sh(lab, lh, "timeout 5 bash -c 'exec 3<>/dev/tcp/10.70.0.10/20022; head -c 7 <&3' | grep -q SSH-2.0 && echo ok", 30)?
    lab.log("bravo's SSH banner read via 10.70.0.10:20022")

    lab.log("ephemeral forwards disappear with the node; the permanent one stays")
    must(lab, alpha, "pkill -x ig-node; sleep 2")?
    wait_sh(lab, lh, admin + "forward list | awk 'NR>1' | grep -c . | grep -qx 1", 60)?
    must_fail(lab, lh, "curl -sS --max-time 3 http://10.70.0.10:" + port + "/hostname")?
    must(lab, alpha, "RUST_LOG=info setsid nohup ig-node run > /var/log/ig-node.log 2>&1 < /dev/null & sleep 1; test -S /run/intergalactic/node.sock")?
    wait_sh(lab, alpha, "ig peers | grep -q online", 30)?
    must_fail(lab, alpha, "ig exposes | grep -q ephemeral")?
    lab.log("alpha restarted without ephemeral forwards, as expected")

    lab.log("a localhost target is refused, and a network can forbid exposes")
    let bad = sh(alpha, "ig expose 127.0.0.1:8080")?
    if bad.exit_code == 0 { return Err("localhost target should be refused") }
    lab.log("refused: " + bad.stderr.trim())
    must(lab, lh, admin + "network expose game --deny")?
    wait_sh(lab, alpha, "ig status | grep -q game", 10)?
    let denied = sh(alpha, "ig expose 8080 --network game")?
    if denied.exit_code == 0 { return Err("expose should have been refused in game") }
    lab.log("game refused: " + denied.stderr.trim())
    must(lab, lh, admin + "forward remove $(" + admin + "forward list | sed -n 2p | cut -d' ' -f1)")?
    lab.log("FORWARD OK")
    Ok(())
}

fn main(lab: Lab) {
    match setup(lab) {
        Ok(_) => lab.log("done"),
        Err(e) => {
            lab.log("FAILED: " + e)
            Err(e).expect("forward lab failed")
        }
    }
}
