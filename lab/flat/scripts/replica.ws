// A second lighthouse (lh2) replicates lh. Nodes connect to both; when lh goes
// down the network keeps working through lh2, joins wait for lh, and lh2 can
// publish forwards of its own. Run after linux.ws and windows.ws.
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

fn setup(lab: Lab) -> Result[unit, string] {
    let lh = lab.vm("lh")?
    let lh2 = lab.vm("lh2")?
    let alpha = lab.vm("alpha")?
    let bravo = lab.vm("bravo")?
    lh2.wait_ready(600)?
    let admin = "ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock "
    let admin2 = "ig-lighthouse --state-dir /var/lib/ig-lh2 --admin-socket /run/ig-lh2.sock "

    // A previous run may have left the primary stopped.
    let up = sh(lh, "pgrep -x ig-lighthouse > /dev/null || (rm -f /run/ig-lh.sock; setsid nohup ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock serve --listen '[::]:7777' --public-host 10.70.0.10 --name lh --dns-domain ig.test --relay-limit-per-node-kbps 20000 > /var/log/ig-lh.log 2>&1 < /dev/null & sleep 2)")?
    wait_sh(lab, lh, admin + "info > /dev/null", 20)?
    let k2 = sh(lh, admin + "lighthouse remove $(" + admin + "lighthouse list | grep lh2 | sed -E 's/.* //' | tr -d '\\n') 2>/dev/null; true")?

    lab.log("install and key the replica")
    let k = sh(lh2, "pkill -x ig-lighthouse; sleep 1; rm -f /usr/local/bin/ig-lighthouse; true")?
    lh2.copy_to("../../bin/ig-lighthouse", "/usr/local/bin/ig-lighthouse")?
    must(lab, lh2, "chmod 755 /usr/local/bin/ig-lighthouse; hostnamectl set-hostname lh2; rm -rf /var/lib/ig-lh2; mkdir -p /var/lib/ig-lh2")?
    let primary_key = must(lab, lh, admin + "info | sed -nE 's/^public key +//p' | tr -d ' \\n'")?
    // Start the replica once to create its key, read it, then register it on the primary.
    must(lab, lh2, "setsid nohup ig-lighthouse --state-dir /var/lib/ig-lh2 --admin-socket /run/ig-lh2.sock serve --listen '[::]:7777' --public-host 10.70.0.13 --name lh2 --dns-domain ig.test --replica-of 10.70.0.10:7777 --primary-key " + primary_key + " > /var/log/ig-lh2.log 2>&1 < /dev/null & sleep 2; test -S /run/ig-lh2.sock")?
    let replica_key = must(lab, lh2, admin2 + "info | sed -nE 's/^public key +//p' | tr -d ' \\n'")?
    lab.log(must(lab, lh, admin + "lighthouse add lh2 10.70.0.13 7777 " + replica_key)?)
    wait_sh(lab, lh, admin + "lighthouse list | grep lh2 | grep -q ' up '", 30)?
    lab.log(must(lab, lh, admin + "lighthouse list")?)
    lab.log("replica view of the store:\n" + wait_sh(lab, lh2, admin2 + "network list | grep -q dev && " + admin2 + "node list", 30)?)

    lab.log("existing nodes learn the second lighthouse and connect to it")
    wait_sh(lab, alpha, "ig networks | grep dev | grep -q 10.70.0.13:7777", 60)?
    wait_sh(lab, alpha, "ig networks | grep dev | grep -v -q down", 60)?
    lab.log(must(lab, alpha, "ig networks")?)
    // lh2 is a member too: it gets an address and a TUN.
    wait_sh(lab, alpha, "ig peers | grep -q lh2", 60)?
    wait_sh(lab, alpha, "ping -c 1 -W 2 lh2.dev.ig.test", 30)?
    lab.log("alpha reached lh2 over the overlay")

    // An invite made now names both lighthouses.
    let game_inv = must(lab, lh, admin + "invite create game --uses 5 --ttl 2h 2>/dev/null | sed 's/^ig join //' | tr -d '\\n'")?
    lab.log("game invite lists: " + must(lab, lh, "ig invite show " + game_inv + " 2>/dev/null | head -1 || echo n/a")?.trim())

    lab.log("the primary goes down")
    must(lab, lh, "pkill -x ig-lighthouse; sleep 1")?
    wait_sh(lab, alpha, "ig networks | grep dev | grep -q '10.70.0.10:7777 (down)'", 60)?
    lab.log(must(lab, alpha, "ig networks")?)
    must(lab, alpha, "ping -c 3 -W 2 10.90.0.4")?
    must(lab, bravo, "ping -c 3 -W 2 10.90.0.3")?
    lab.log("alpha and bravo still talk with the primary down")
    // A new path: restart bravo's daemon so it must rediscover alpha through lh2.
    must(lab, bravo, "pkill -x ig-node; sleep 1; RUST_LOG=info setsid nohup ig-node run > /var/log/ig-node.log 2>&1 < /dev/null & sleep 1; test -S /run/intergalactic/node.sock")?
    wait_sh(lab, bravo, "ping -c 1 -W 2 10.90.0.3", 60)?
    lab.log("bravo restarted and found alpha again through lh2")
    // Joins need the primary: a clear refusal, not a hang. bravo is not in game.
    let j = sh(bravo, "ig join " + game_inv)?
    if j.exit_code == 0 { return Err("join should fail while the primary is down") }
    lab.log("join refused: " + j.stderr.trim())
    // A forward published by the replica works without the primary.
    let eout = must(lab, alpha, "ig expose 8080 --lighthouse lh2 | tee /tmp/expose2.out")?
    lab.log(eout.trim())
    let port = must(lab, alpha, "head -1 /tmp/expose2.out | sed -E 's#^tcp://[^ ]*:([0-9]+)  ->.*#\\1#' | tr -d '\\n'")?
    must(lab, alpha, "test -f /run/http.pid && kill $(cat /run/http.pid); setsid nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory /etc > /var/log/http.log 2>&1 < /dev/null & echo $! > /run/http.pid; sleep 1")?
    wait_sh(lab, lh2, "curl -sS --max-time 4 http://10.70.0.13:" + port + "/hostname | grep -qx alpha", 30)?
    lab.log("forward on lh2 works while the primary is down")

    lab.log("the primary comes back; joins work again")
    must(lab, lh, "setsid nohup ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock serve --listen '[::]:7777' --public-host 10.70.0.10 --name lh --dns-domain ig.test --relay-limit-per-node-kbps 20000 > /var/log/ig-lh.log 2>&1 < /dev/null & sleep 2; test -S /run/ig-lh.sock")?
    wait_sh(lab, alpha, "ig networks | grep dev | grep -v -q down", 60)?
    wait_sh(lab, bravo, "ig join " + game_inv, 30)?
    lab.log(must(lab, bravo, "ig networks")?)
    lab.log(must(lab, lh, admin + "lighthouse list")?)
    lab.log("REPLICA OK")
    Ok(())
}

fn main(lab: Lab) {
    match setup(lab) {
        Ok(_) => lab.log("done"),
        Err(e) => {
            lab.log("FAILED: " + e)
            Err(e).expect("replica lab failed")
        }
    }
}
