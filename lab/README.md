# Virtual labs

Real-machine verification with [vmlab](https://vmlab.io): QEMU/KVM guests on virtual
segments, driven by wscript. Everything the unit tests cannot cover runs here:
real TUN devices, the OS resolver, the Windows service, Wintun, firewalls, and NAT.

Build the guest binaries first. Linux guests get static musl builds, Windows gets the
mingw build plus `wintun.dll` from <https://www.wintun.net/>:

```sh
CC_x86_64_unknown_linux_musl=gcc cargo build --release --target x86_64-unknown-linux-musl -p ig-node -p ig-cli -p ig-lighthouse
cargo build --release --target x86_64-pc-windows-gnu -p ig-node -p ig-cli
mkdir -p lab/bin
cp target/x86_64-unknown-linux-musl/release/{ig,ig-node,ig-lighthouse} lab/bin/
cp target/x86_64-pc-windows-gnu/release/{ig,ig-node}.exe lab/bin/
cp /path/to/wintun/bin/amd64/wintun.dll lab/bin/
```

`just lab::bins` does the Rust part.

## flat: one segment, Linux and Windows nodes

`lab/flat`: a lighthouse VM (`lh`), two Ubuntu 24.04 nodes (`alpha`, `bravo`) and a
Windows Server 2025 node (`win`) on one segment.

```sh
cd lab/flat
vmlab up                          # pulls the published templates on first use
vmlab script scripts/linux.ws     # lighthouse, networks, invites, two nodes
vmlab script scripts/windows.ws   # service install, join, DNS, traffic, restart
vmlab down
```

`linux.ws` checks: both nodes join `dev` (IPv4 + IPv6) and `game`; interfaces carry the
assigned addresses; systemd-resolved is configured per interface; ping over IPv4 and IPv6;
the path becomes `direct`; forward and reverse DNS through the resolver; HTTP over IPv4
and IPv6 by name; the `game` policy (icmp only) lets ping through and blocks TCP; a `dev`
address is unreachable through the `game` interface; leaving a network removes the peer.

`windows.ws` checks: `ig-node service install` registers and starts the service as
LocalSystem; the Wintun adapter carries both addresses; ping to a Linux peer over IPv4
and IPv6; NRPT rules exist and `Resolve-DnsName` answers; the Linux peer reaches Windows
by address and by name (the daemon adds a firewall rule for its interface); `service
stop` then `service start`; the restarted node is reachable again within a second.

## nat: two nodes behind two NATs

`lab/nat`: `alpha` and `bravo` each on their own NAT'd segment, with the lighthouse on
the host so both reach it the way they would reach a VPS.

```sh
./lab/nat/run.sh                  # starts the host lighthouse, brings the lab up, runs scripts/nat.ws
```

The vmlab NAT is not full-cone, so this lab does not produce a direct path; it shows both
nodes falling back to the relay and exchanging IPv4 traffic, HTTP and DNS through it, then
repeats the exchange with `--relay-only`. Direct paths across NATs are exercised by the
`flat` lab (same segment) and by the loopback tests in `crates/ig-tests`.

## Results on 2026-10-20

All three scripts pass on this machine (vmlab 0.30.0-alpha, KVM, Ubuntu 24.04 and
Windows Server 2025 templates). Bugs found and fixed by these labs:

- The Windows service did not exit on stop: the tokio runtime waited forever during
  teardown. Shutdown is now bounded, the service reports StopPending, and a watchdog exits
  the process if teardown stalls.
- `service stop` returned before the service had stopped, so an immediate `service start`
  failed. It now waits for the Stopped state.
- Windows Firewall dropped inbound traffic on the new adapter. The daemon adds an inbound
  allow rule per overlay interface and removes it on leave and uninstall.
- A peer that restarted on a new UDP port stayed unreachable for up to 30 s. The engine
  now drops the stale direct path and renegotiates as soon as the lighthouse reports the
  new endpoints.
- Two networks with the same name (for example after a lighthouse was re-keyed) collided
  on the interface name. Names now get a numeric suffix when taken.
