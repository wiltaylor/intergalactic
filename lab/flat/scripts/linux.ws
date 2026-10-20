// Lighthouse plus two Linux nodes: join, IPv4/IPv6 traffic, DNS, policy, direct path.
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

fn install_linux(m: Machine) -> Result[unit, string] {
    // Stop anything still running from a previous run before overwriting.
    let k = sh(m, "pkill -x ig-node; pkill -x ig-lighthouse; test -f /run/http.pid && kill $(cat /run/http.pid); sleep 1; pkill -9 -x ig-node; pkill -9 -x ig-lighthouse; rm -f /usr/local/bin/ig /usr/local/bin/ig-node /usr/local/bin/ig-lighthouse; true")?
    m.copy_to("../../bin/ig-node", "/usr/local/bin/ig-node")?
    m.copy_to("../../bin/ig", "/usr/local/bin/ig")?
    m.copy_to("../../bin/ig-lighthouse", "/usr/local/bin/ig-lighthouse")?
    let r = sh(m, "chmod 755 /usr/local/bin/ig /usr/local/bin/ig-node /usr/local/bin/ig-lighthouse")?
    if r.exit_code != 0 { return Err("chmod failed: " + r.stderr) }
    Ok(())
}

fn start_node(lab: Lab, m: Machine, dev_inv: string, game_inv: string) -> Result[unit, string] {
    lab.log("starting node on " + m.name())
    must(lab, m, "hostnamectl set-hostname " + m.name())?
    must(lab, m, "pkill -x ig-node; sleep 0.5; rm -rf /var/lib/intergalactic; mkdir -p /run/intergalactic; RUST_LOG=info setsid nohup ig-node run > /var/log/ig-node.log 2>&1 < /dev/null & sleep 1; test -S /run/intergalactic/node.sock")?
    let j1 = must(lab, m, "ig join " + dev_inv)?
    lab.log(fmt("{}: {}", m.name(), j1.trim()))
    let j2 = must(lab, m, "ig join " + game_inv)?
    lab.log(fmt("{}: {}", m.name(), j2.trim()))
    Ok(())
}

fn wait_node(lab: Lab, m: Machine) -> Result[unit, string] {
    wait_sh(lab, m, "ip -br addr show ig-dev | grep -q 10.90.0 && ip -br addr show ig-dev | grep -q fd42:9a:1 && ip -br addr show ig-game | grep -q 10.91.0", 30)?
    wait_sh(lab, m, "ig peers | grep -q online", 30)?
    Ok(())
}

fn setup(lab: Lab) -> Result[unit, string] {
    let lh = lab.vm("lh")?
    let alpha = lab.vm("alpha")?
    let bravo = lab.vm("bravo")?
    lh.wait_ready(600)?
    alpha.wait_ready(600)?
    bravo.wait_ready(600)?

    lab.log("installing binaries")
    install_linux(lh)?
    install_linux(alpha)?
    install_linux(bravo)?

    lab.log("starting lighthouse on lh (10.70.0.10)")
    let lhcmd = "pkill -x ig-lighthouse; sleep 0.5; rm -rf /var/lib/ig-lh; mkdir -p /var/lib/ig-lh; setsid nohup ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock serve --listen '[::]:7777' --public-host 10.70.0.10 --dns-domain ig.test --relay-limit-per-node-kbps 20000 > /var/log/ig-lh.log 2>&1 < /dev/null & sleep 1; test -S /run/ig-lh.sock"
    must(lab, lh, lhcmd)?
    let admin = "ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock "
    must(lab, lh, admin + "network create dev 10.90.0.0/24 --ipv6 fd42:9a:1::/64")?
    must(lab, lh, admin + "network create game 10.91.0.0/24")?
    must(lab, lh, admin + "network policy game --allow icmp")?
    must(lab, lh, admin + "network relay-limit game --per-node-kbps 500")?
    let dev_inv = must(lab, lh, admin + "invite create dev --uses 5 --ttl 2h 2>/dev/null | sed 's/^ig join //' | tr -d '\\n' | tee /root/invite-dev.txt")?
    let game_inv = must(lab, lh, admin + "invite create game --uses 5 --ttl 2h 2>/dev/null | sed 's/^ig join //' | tr -d '\\n' | tee /root/invite-game.txt")?
    lab.log("dev invite: " + dev_inv)

    start_node(lab, alpha, dev_inv, game_inv)?
    start_node(lab, bravo, dev_inv, game_inv)?

    lab.log("waiting for interfaces and peers")
    wait_node(lab, alpha)?
    wait_node(lab, bravo)?
    let addrs = must(lab, alpha, "ip -br addr show ig-dev; ip -br addr show ig-game; resolvectl status ig-dev | sed -n '1,12p'")?
    lab.log("alpha interfaces:\n" + addrs)

    // Addresses are allocated in join order: alpha .2, bravo .3.
    lab.log("IPv4 over dev")
    must(lab, alpha, "ping -c 3 -W 3 10.90.0.3")?
    lab.log("IPv6 over dev")
    must(lab, alpha, "ping -c 3 -W 3 fd42:9a:1::3")?
    lab.log("direct path established?")
    let st = wait_sh(lab, alpha, "ig peers | grep -q direct", 30)?
    lab.log(must(lab, alpha, "ig status")?)

    lab.log("peer DNS through systemd-resolved")
    let q = must(lab, alpha, "resolvectl query bravo.dev.ig.test")?
    lab.log(q)
    if !q.contains("10.90.0.3") { return Err("resolvectl did not return bravo's dev address: " + q) }
    if !q.contains("fd42:9a:1::3") { return Err("resolvectl did not return bravo's IPv6 address: " + q) }
    must(lab, alpha, "ping -c 2 -W 3 bravo.dev.ig.test")?
    must(lab, alpha, "ping -c 2 -W 3 bravo.game.ig.test")?
    let rq = must(lab, alpha, "resolvectl query 10.90.0.3")?
    if !rq.contains("bravo.dev.ig.test") { return Err("reverse lookup failed: " + rq) }
    lab.log("reverse: " + rq.trim())

    lab.log("TCP over dev (allow all) and over game (icmp only)")
    must(lab, bravo, "test -f /run/http.pid && kill $(cat /run/http.pid); setsid nohup python3 -m http.server 8080 --bind :: --directory /etc > /var/log/http.log 2>&1 < /dev/null & echo $! > /run/http.pid; sleep 1")?
    let body = must(lab, alpha, "curl -sS --max-time 5 http://bravo.dev.ig.test:8080/hostname")?
    if body.trim() != "bravo" { return Err("unexpected body over dev: " + body) }
    lab.log("GET /etc/hostname over dev -> " + body.trim())
    let body6 = must(lab, alpha, "curl -sS --max-time 5 'http://[fd42:9a:1::3]:8080/hostname'")?
    if body6.trim() != "bravo" { return Err("unexpected body over IPv6: " + body6) }
    lab.log("GET over IPv6 -> " + body6.trim())
    must(lab, alpha, "ping -c 2 -W 3 10.91.0.3")?
    must_fail(lab, alpha, "curl -sS --max-time 4 http://10.91.0.3:8080/hostname")?
    lab.log("game network: ping allowed, TCP blocked by policy")

    lab.log("isolation: a dev address is unreachable through the game interface")
    must_fail(lab, alpha, "ping -c 1 -W 2 -I ig-game 10.90.0.3")?

    lab.log("leave game on bravo; alpha should lose the game peer address")
    must(lab, bravo, "ig leave game")?
    wait_sh(lab, alpha, "! ig peers | grep -q 10.91.0.3", 30)?
    must(lab, alpha, "ping -c 1 -W 2 10.90.0.3")?

    let nodes = must(lab, lh, admin + "node list")?
    lab.log("lighthouse node list:\n" + nodes)
    lab.log("LINUX OK")
    Ok(())
}

fn main(lab: Lab) {
    match setup(lab) {
        Ok(_) => lab.log("done"),
        Err(e) => {
            lab.log("FAILED: " + e)
            Err(e).expect("linux lab failed")
        }
    }
}
