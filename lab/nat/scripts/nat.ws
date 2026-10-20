// Two nodes behind two netfilter NATs, lighthouse on the WAN.
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

fn install(m: Machine) -> Result[unit, string] {
    let k = sh(m, "pkill -x ig-node; pkill -x ig-lighthouse; sleep 1; pkill -9 -x ig-node; pkill -9 -x ig-lighthouse; rm -f /usr/local/bin/ig /usr/local/bin/ig-node /usr/local/bin/ig-lighthouse; true")?
    m.copy_to("../../bin/ig-node", "/usr/local/bin/ig-node")?
    m.copy_to("../../bin/ig", "/usr/local/bin/ig")?
    m.copy_to("../../bin/ig-lighthouse", "/usr/local/bin/ig-lighthouse")?
    let r = sh(m, "chmod 755 /usr/local/bin/ig /usr/local/bin/ig-node /usr/local/bin/ig-lighthouse")?
    if r.exit_code != 0 { return Err("chmod failed: " + r.stderr) }
    Ok(())
}

// Turn an Ubuntu VM into a masquerading router between its LAN and the WAN.
fn make_router(lab: Lab, m: Machine, lan: string, wan_ip: string) -> Result[unit, string] {
    must(lab, m, "hostnamectl set-hostname " + m.name())?
    m.copy_to("router.sh", "/root/router.sh")?
    let out = must(lab, m, "sh /root/router.sh " + lan + " " + wan_ip)?
    lab.log(fmt("{}: {}", m.name(), out.trim()))
    Ok(())
}

fn start_node(lab: Lab, m: Machine, flags: string, invite: string) -> Result[unit, string] {
    must(lab, m, "hostnamectl set-hostname " + m.name())?
    must(lab, m, "pkill -x ig-node; sleep 1; rm -rf /var/lib/intergalactic; mkdir -p /run/intergalactic; RUST_LOG=info setsid nohup ig-node run " + flags + " > /var/log/ig-node.log 2>&1 < /dev/null & sleep 1; test -S /run/intergalactic/node.sock")?
    let j = must(lab, m, "ig join " + invite)?
    lab.log(fmt("{}: {}", m.name(), j.trim()))
    Ok(())
}

fn restart_node(lab: Lab, m: Machine, flags: string) -> Result[unit, string] {
    must(lab, m, "pkill -x ig-node; sleep 1; RUST_LOG=info setsid nohup ig-node run " + flags + " > /var/log/ig-node.log 2>&1 < /dev/null & sleep 1; test -S /run/intergalactic/node.sock")?
    Ok(())
}

fn exchange(lab: Lab, alpha: Machine, bravo: Machine, label: string) -> Result[unit, string] {
    wait_sh(lab, alpha, "ig peers | grep -q online", 30)?
    wait_sh(lab, bravo, "ig peers | grep -q online", 30)?
    wait_sh(lab, alpha, "ping -c 1 -W 2 10.90.0.3", 30)?
    must(lab, alpha, "ping -c 3 -W 3 10.90.0.3")?
    must(lab, bravo, "ping -c 3 -W 3 10.90.0.2")?
    must(lab, bravo, "test -f /run/http.pid && kill $(cat /run/http.pid); setsid nohup python3 -m http.server 8080 --bind :: --directory /etc > /var/log/http.log 2>&1 < /dev/null & echo $! > /run/http.pid; sleep 1")?
    let body = must(lab, alpha, "curl -sS --max-time 5 http://bravo.dev.ig.test:8080/hostname")?
    if body.trim() != "bravo" { return Err("unexpected body: " + body) }
    lab.log(fmt("[{}] ping both ways, TCP by DNS name OK", label))
    Ok(())
}

fn setup(lab: Lab) -> Result[unit, string] {
    let lh = lab.vm("lh")?
    let rta = lab.vm("rta")?
    let rtb = lab.vm("rtb")?
    let alpha = lab.vm("alpha")?
    let bravo = lab.vm("bravo")?
    for m in lab.vms() { m.wait_ready(600)? }

    lab.log("routers")
    make_router(lab, rta, "10.81.0.1", "10.99.0.2")?
    make_router(lab, rtb, "10.82.0.1", "10.99.0.3")?
    lab.log("alpha routes:\n" + must(lab, alpha, "ip route")?)
    // Through the NAT: alpha reaches the lighthouse on the WAN, but not bravo's LAN.
    must(lab, alpha, "ping -c 1 -W 2 10.99.0.10")?
    let leak = sh(alpha, "ping -c 1 -W 1 10.82.0.11")?
    if leak.exit_code == 0 { return Err("LANs are not isolated; the NAT test would be meaningless") }
    lab.log("alpha reaches the WAN through rta and cannot reach bravo's LAN")

    lab.log("lighthouse on lh (10.99.0.10)")
    install(lh)?
    install(alpha)?
    install(bravo)?
    must(lab, lh, "rm -rf /var/lib/ig-lh; mkdir -p /var/lib/ig-lh; setsid nohup ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock serve --listen '[::]:7777' --public-host 10.99.0.10 --dns-domain ig.test > /var/log/ig-lh.log 2>&1 < /dev/null & sleep 1; test -S /run/ig-lh.sock")?
    let admin = "ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock "
    must(lab, lh, admin + "network create dev 10.90.0.0/24 --ipv6 fd42:9a:1::/64")?
    let invite = must(lab, lh, admin + "invite create dev --uses 5 --ttl 2h 2>/dev/null | sed 's/^ig join //' | tr -d '\\n'")?

    lab.log("phase 1: hole punching through two NATs")
    start_node(lab, alpha, "", invite)?
    start_node(lab, bravo, "", invite)?
    exchange(lab, alpha, bravo, "normal")?
    wait_sh(lab, alpha, "ig peers | grep -q direct", 60)?
    wait_sh(lab, bravo, "ig peers | grep -q direct", 60)?
    let pa = must(lab, alpha, "ig peers")?
    let pb = must(lab, bravo, "ig peers")?
    lab.log("alpha peers:\n" + pa)
    lab.log("bravo peers:\n" + pb)
    // The direct endpoint must be the other router's WAN address: traffic
    // crosses both NATs without the lighthouse.
    if !pa.contains("10.99.0.3:") { return Err("alpha's direct endpoint is not bravo's NAT address:\n" + pa) }
    if !pb.contains("10.99.0.2:") { return Err("bravo's direct endpoint is not alpha's NAT address:\n" + pb) }
    must(lab, alpha, "ping -c 5 -i 0.2 -W 2 10.90.0.3")?
    must(lab, alpha, "ping -c 3 -W 3 fd42:9a:1::3")?
    lab.log(must(lab, lh, admin + "node list")?)
    lab.log(must(lab, alpha, "grep -E 'direct path|public endpoint|falling back|renegotiat' /var/log/ig-node.log | tail -6")?)

    lab.log("phase 2: relay-only on both sides")
    restart_node(lab, alpha, "--relay-only")?
    restart_node(lab, bravo, "--relay-only")?
    exchange(lab, alpha, bravo, "relay-only")?
    let pr = must(lab, alpha, "ig peers")?
    if !pr.contains("relay") { return Err("expected relay path in relay-only mode:\n" + pr) }
    lab.log("relay-only peers:\n" + pr)

    lab.log("phase 3: back to normal; the direct path must come back")
    restart_node(lab, alpha, "")?
    restart_node(lab, bravo, "")?
    exchange(lab, alpha, bravo, "normal again")?
    wait_sh(lab, alpha, "ig peers | grep -q direct", 60)?
    lab.log("NAT OK")
    Ok(())
}

fn main(lab: Lab) {
    match setup(lab) {
        Ok(_) => lab.log("done"),
        Err(e) => {
            lab.log("FAILED: " + e)
            Err(e).expect("nat lab failed")
        }
    }
}
