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

`gateway.ws` (run after the two above) checks gateway devices: alpha and bravo restart with
`--gateway`; the lighthouse VM itself (not a member) is registered as device `lhbox`; the
active gateway installs `ip_forward` and the `ig_gateway` nftables table; the Windows node
fetches a file from the device by name through the gateway; alpha's link goes down and within
the 45 s idle timeout the device moves to bravo while Windows keeps working; bravo reaches its
own device through the kernel DNAT; alpha returns and the active gateway stays with bravo.

`windows.ws` checks: `ig-node service install` registers and starts the service as
LocalSystem; the Wintun adapter carries both addresses; ping to a Linux peer over IPv4
and IPv6; NRPT rules exist and `Resolve-DnsName` answers; the Linux peer reaches Windows
by address and by name (the daemon adds a firewall rule for its interface); `service
stop` then `service start`; the restarted node is reachable again within a second.

## nat: two nodes behind two real NATs

`lab/nat`: a lighthouse VM on a `wan` segment, two Ubuntu router VMs (`rta`, `rtb`) that
masquerade between their LAN and the WAN with nftables and drop unsolicited WAN input,
and one node behind each router.

```sh
cd lab/nat
vmlab up
vmlab script scripts/nat.ws
vmlab down
```

Phase 1 proves hole punching: both nodes reach each other and `ig peers` shows `direct`
with the other router's WAN address and NAT-assigned port as the endpoint. Phase 2 restarts
both nodes with `--relay-only` and checks traffic still flows through the lighthouse. Phase
3 removes the flag and checks the direct path comes back.

Finding: with a router that accepts unsolicited WAN packets into its own input path (no
firewall), the early punch from one side confirms a stray conntrack entry that occupies the
other side's port mapping, and the punch from that side leaves on a different port. Real
home routers drop such packets before conntrack confirms them, which is what `router.sh`
does, and then both NATs keep the port and the punch succeeds.

## android: the app on an emulator

`lab/android`: one Linux node on a NAT'd segment plus the Android app on an x86_64 emulator.
The lighthouse runs on the host; the node reaches it through the vmlab NAT and the emulator
reaches it as `10.0.2.2`.

```sh
export ANDROID_HOME=...   # with emulator, platform-tools and an AVD named "ig" (API 35, x86_64)
cargo build --release -p ig-lighthouse -p ig-cli
./lab/android/run.sh
```

The script installs the debug APK, launches the activity with the invite as an intent
extra (`--es invite ... --ez connect true`), accepts the VPN consent dialog, and then checks:
`tun0` carries both addresses; ping from the emulator to the node over IPv4 and IPv6; the
node's name resolves through the VPN's DNS server; the node pings the emulator and resolves
its name; the lighthouse lists both members.

## Results on 2026-10-20

All five scenarios pass on this machine (vmlab 0.30.0-alpha, KVM, Ubuntu 24.04 and
Windows Server 2025 templates, Android 35 emulator). Bugs found and fixed by these labs:

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
- On Android, `attachTun` was called from the main thread outside the tokio runtime and
  the app crashed when the VPN came up. The mobile bindings now enter the runtime for
  every call that touches the engine.
