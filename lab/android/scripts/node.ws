// Start the Linux node and join with the invite run.sh wrote to ../invite.txt.
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

fn setup(lab: Lab) -> Result[unit, string] {
    let alpha = lab.vm("alpha")?
    alpha.wait_ready(600)?
    let k = sh(alpha, "pkill -x ig-node; sleep 1; pkill -9 -x ig-node; rm -f /usr/local/bin/ig /usr/local/bin/ig-node; true")?
    alpha.copy_to("../../bin/ig-node", "/usr/local/bin/ig-node")?
    alpha.copy_to("../../bin/ig", "/usr/local/bin/ig")?
    alpha.copy_to("../invite.txt", "/root/invite.txt")?
    must(lab, alpha, "chmod 755 /usr/local/bin/ig /usr/local/bin/ig-node; hostnamectl set-hostname alpha")?
    must(lab, alpha, "rm -rf /var/lib/intergalactic; mkdir -p /run/intergalactic; RUST_LOG=info setsid nohup ig-node run > /var/log/ig-node.log 2>&1 < /dev/null & sleep 1; test -S /run/intergalactic/node.sock")?
    lab.log(must(lab, alpha, "ig join $(cat /root/invite.txt)")?)
    Ok(())
}

fn main(lab: Lab) {
    match setup(lab) {
        Ok(_) => lab.log("done"),
        Err(e) => {
            lab.log("FAILED: " + e)
            Err(e).expect("android lab node failed")
        }
    }
}
