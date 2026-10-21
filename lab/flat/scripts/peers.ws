// Two lighthouses as equal peers. lh2 registers with lh and the two merge their
// stores; nodes connect to both. When lh goes down, lh2 keeps serving: joins,
// admin changes and forwards all work on lh2 alone, and lh catches up when it
// returns. A partition between the two lighthouses while both stay up ends with
// identical stores. Run after linux.ws and windows.ws.
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

fn start_lh(lab: Lab, lh: Machine) -> Result[string, string] {
    must(lab, lh, "pgrep -x ig-lighthouse > /dev/null || (rm -f /run/ig-lh.sock; setsid nohup ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock serve --listen '[::]:7777' --public-host 10.70.0.10 --name lh --dns-domain ig.test --relay-limit-per-node-kbps 20000 > /var/log/ig-lh.log 2>&1 < /dev/null & sleep 2); test -S /run/ig-lh.sock")
}

fn setup(lab: Lab) -> Result[unit, string] {
    let lh = lab.vm("lh")?
    let lh2 = lab.vm("lh2")?
    let alpha = lab.vm("alpha")?
    let bravo = lab.vm("bravo")?
    lh2.wait_ready(600)?
    let admin = "ig-lighthouse --state-dir /var/lib/ig-lh --admin-socket /run/ig-lh.sock "
    let admin2 = "ig-lighthouse --state-dir /var/lib/ig-lh2 --admin-socket /run/ig-lh2.sock "

    // A previous run may have left lh stopped, or lh2 registered.
    start_lh(lab, lh)?
    wait_sh(lab, lh, admin + "info > /dev/null", 20)?
    let k2 = sh(lh, admin + "lighthouse remove $(" + admin + "lighthouse list | grep lh2 | sed -E 's/.* //' | tr -d '\\n') 2>/dev/null; true")?
    let k3 = sh(lh, "for d in lh2box pa pb dup; do " + admin + "device remove dev $d; done 2>/dev/null; true")?
    let k4 = sh(bravo, "ig leave game 2>/dev/null; true")?
    let k5 = sh(lh, admin + "network delete tmp 2>/dev/null; true")?

    lab.log("install lh2 and start it on its own")
    let k = sh(lh2, "pkill -x ig-lighthouse; sleep 1; rm -f /usr/local/bin/ig-lighthouse; true")?
    lh2.copy_to("../../bin/ig-lighthouse", "/usr/local/bin/ig-lighthouse")?
    lh.copy_to("partition.sh", "/usr/local/bin/partition.sh")?
    must(lab, lh, "chmod 755 /usr/local/bin/partition.sh; partition.sh off")?
    must(lab, lh2, "chmod 755 /usr/local/bin/ig-lighthouse; hostnamectl set-hostname lh2; rm -rf /var/lib/ig-lh2; mkdir -p /var/lib/ig-lh2")?
    must(lab, lh2, "setsid nohup ig-lighthouse --state-dir /var/lib/ig-lh2 --admin-socket /run/ig-lh2.sock serve --listen '[::]:7777' --public-host 10.70.0.13 --name lh2 --dns-domain ig.test --relay-limit-per-node-kbps 20000 > /var/log/ig-lh2.log 2>&1 < /dev/null & sleep 2; test -S /run/ig-lh2.sock")?
    let key1 = must(lab, lh, admin + "info | sed -nE 's/^public key +//p' | tr -d ' \\n'")?
    let key2 = must(lab, lh2, admin2 + "info | sed -nE 's/^public key +//p' | tr -d ' \\n'")?

    lab.log("each lighthouse registers the other; the stores merge")
    lab.log(must(lab, lh, admin + "lighthouse add lh2 10.70.0.13 7777 " + key2)?)
    lab.log(must(lab, lh2, admin2 + "lighthouse add lh 10.70.0.10 7777 " + key1)?)
    wait_sh(lab, lh, admin + "lighthouse list | grep lh2 | grep -q ' up '", 30)?
    wait_sh(lab, lh2, admin2 + "lighthouse list | grep '^lh ' | grep -q ' up '", 30)?
    lab.log(must(lab, lh, admin + "lighthouse list")?)
    lab.log("lh2 view of the store:\n" + wait_sh(lab, lh2, admin2 + "network list | grep -q dev && " + admin2 + "node list", 30)?)

    lab.log("existing nodes learn the second lighthouse and connect to it")
    wait_sh(lab, alpha, "ig networks | grep dev | grep -q 10.70.0.13:7777", 60)?
    wait_sh(lab, alpha, "ig networks | grep dev | grep -v -q down", 60)?
    lab.log(must(lab, alpha, "ig networks")?)
    wait_sh(lab, alpha, "ig peers | grep -q lh2", 60)?
    wait_sh(lab, alpha, "ping -c 1 -W 2 lh2.dev.ig.test", 30)?
    lab.log("alpha reached lh2 over the overlay")

    lab.log("a change on lh2 shows up on lh")
    must(lab, lh2, admin2 + "device add dev lh2box 10.70.0.13")?
    wait_sh(lab, lh, admin + "device list dev | grep -q lh2box", 30)?
    // No node runs as a gateway yet (gateway.ws comes later), so check the name only.
    wait_sh(lab, alpha, "resolvectl query lh2box.dev.ig.test | grep -q 10.90.0.", 30)?
    lab.log("alpha resolves the device registered on lh2")

    // An invite made on lh2 names both lighthouses.
    let game_inv = must(lab, lh2, admin2 + "invite create game --uses 5 --ttl 2h 2>/dev/null | sed 's/^ig join //' | tr -d '\\n'")?

    lab.log("lh goes down; lh2 serves alone")
    must(lab, lh, "pkill -x ig-lighthouse; sleep 1")?
    wait_sh(lab, alpha, "ig networks | grep dev | grep -q '10.70.0.10:7777 (down)'", 60)?
    wait_sh(lab, lh2, admin2 + "lighthouse list | grep '^lh ' | grep -q ' down '", 60)?
    must(lab, alpha, "ping -c 3 -W 2 10.90.0.4")?
    must(lab, bravo, "ping -c 3 -W 2 10.90.0.3")?
    lab.log("alpha and bravo still talk")
    must(lab, bravo, "pkill -x ig-node; sleep 1; RUST_LOG=info setsid nohup ig-node run > /var/log/ig-node.log 2>&1 < /dev/null & sleep 1; test -S /run/intergalactic/node.sock")?
    wait_sh(lab, bravo, "ping -c 1 -W 2 10.90.0.3", 60)?
    lab.log("bravo restarted and found alpha again through lh2")
    // A join through lh2 alone succeeds (bravo is not in game).
    lab.log(must(lab, bravo, "ig join " + game_inv)?)
    wait_sh(lab, bravo, "ig networks | grep -q game", 30)?
    let game_addr = must(lab, bravo, "ig networks | grep '^game ' | tr -s ' ' | cut -d' ' -f2 | cut -d/ -f1 | tr -d '\\n'")?
    lab.log("bravo joined game through lh2 as " + game_addr)
    // Admin writes work on lh2 alone.
    must(lab, lh2, admin2 + "network create tmp 10.95.0.0/24")?
    // A forward published by lh2 works too.
    let eout = must(lab, alpha, "ig expose 8080 --lighthouse lh2 | tee /tmp/expose2.out")?
    lab.log(eout.trim())
    let port = must(lab, alpha, "head -1 /tmp/expose2.out | sed -E 's#^tcp://[^ ]*:([0-9]+)  ->.*#\\1#' | tr -d '\\n'")?
    must(lab, alpha, "test -f /run/http.pid && kill $(cat /run/http.pid); setsid nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory /etc > /var/log/http.log 2>&1 < /dev/null & echo $! > /run/http.pid; sleep 1")?
    wait_sh(lab, lh2, "curl -sS --max-time 4 http://10.70.0.13:" + port + "/hostname | grep -qx alpha", 30)?
    lab.log("forward on lh2 works with lh down")

    lab.log("lh comes back and catches up")
    start_lh(lab, lh)?
    wait_sh(lab, lh, admin + "lighthouse list | grep lh2 | grep -q ' up '", 60)?
    wait_sh(lab, lh, admin + "network list | grep -q tmp", 30)?
    wait_sh(lab, lh, admin + "node list game | grep bravo | grep -q " + game_addr, 30)?
    lab.log(must(lab, lh, admin + "node list game")?)
    wait_sh(lab, alpha, "ig networks | grep dev | grep -v -q down", 60)?
    must(lab, lh, admin + "network delete tmp")?
    wait_sh(lab, lh2, admin2 + "network list | grep -v -q tmp", 30)?
    lab.log("lh learned the join and the new network; a delete on lh reached lh2")

    lab.log("partition: both lighthouses up, the link between them cut")
    must(lab, lh, "partition.sh on 10.70.0.13")?
    wait_sh(lab, lh, admin + "lighthouse list | grep lh2 | grep -q ' down '", 90)?
    wait_sh(lab, lh2, admin2 + "lighthouse list | grep '^lh ' | grep -q ' down '", 90)?
    must(lab, lh, admin + "device add dev pa 10.70.0.101")?
    must(lab, lh2, admin2 + "device add dev pb 10.70.0.102")?
    must(lab, lh, admin + "device add dev dup 10.70.0.103")?
    must(lab, lh2, admin2 + "device add dev dup 10.70.0.103")?
    must(lab, lh, "partition.sh off")?
    wait_sh(lab, lh, admin + "lighthouse list | grep lh2 | grep -q ' up '", 60)?
    wait_sh(lab, lh, admin + "device list dev | grep -q pb", 30)?
    wait_sh(lab, lh2, admin2 + "device list dev | grep -q pa", 30)?
    vmlab::sleep_ms(2000)
    let d1 = must(lab, lh, admin + "device list dev | tail -n +2 | tr -s ' ' | cut -d' ' -f2-4 | sort")?
    let d2 = must(lab, lh2, admin2 + "device list dev | tail -n +2 | tr -s ' ' | cut -d' ' -f2-4 | sort")?
    if d1 != d2 { return Err("device lists differ after the partition healed:\nlh:\n" + d1 + "\nlh2:\n" + d2) }
    let dups = must(lab, lh, admin + "device list dev | tail -n +2 | tr -s ' ' | cut -d' ' -f2 | grep -cx dup | tr -d ' \\n'")?
    if dups != "1" { return Err("expected exactly one `dup` device, got " + dups) }
    lab.log("both lighthouses agree after the partition:\n" + d1)

    lab.log("clean up the lab devices on lh; the removals reach lh2")
    must(lab, lh, admin + "device remove dev pa; " + admin + "device remove dev pb; " + admin + "device remove dev dup; " + admin + "device remove dev lh2box")?
    wait_sh(lab, lh2, admin2 + "device list dev | grep -v -q -E 'pa|pb|dup|lh2box'", 30)?
    lab.log(must(lab, lh, admin + "lighthouse list")?)
    lab.log("PEERS OK")
    Ok(())
}

fn main(lab: Lab) {
    match setup(lab) {
        Ok(_) => lab.log("done"),
        Err(e) => {
            lab.log("FAILED: " + e)
            Err(e).expect("peers lab failed")
        }
    }
}
