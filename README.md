# Intergalactic

Intergalactic is a self-hosted overlay network, in the spirit of Tailscale, written in Rust.

- A **lighthouse** runs on a VPS. It coordinates members, helps with NAT traversal and relays traffic when a direct path is not possible.
- **Nodes** (Linux, Windows, Android) connect to the lighthouse and talk to each other over WireGuard.
- One lighthouse hosts **many networks**. A device can join several networks at the same time. Each network has its own address range and its own traffic policy, so a `dev` network, a set of ephemeral containers and a `game` network with untrusted devices never see each other.

The lighthouse never holds data-plane keys. It cannot read relayed traffic.

## Components

| Crate | Binary | Role |
| --- | --- | --- |
| `ig-proto` | | Identities, invite format, wire protocols |
| `ig-core` | | Node engine: WireGuard sessions, routing, NAT traversal, policy filter |
| `ig-lighthouse` | `ig-lighthouse` | Coordination server plus its admin CLI |
| `ig-node` | `ig-node` | Node daemon for Linux and Windows (real TUN devices) |
| `ig-cli` | `ig` | Command line for the node daemon |
| `ig-mobile` | `libig_mobile.so` | UniFFI bindings for the Android app |
| `android/` | APK | Android client (`VpnService`) |

## Build

```sh
cargo build --release -p ig-cli -p ig-node -p ig-lighthouse
# Windows (from Linux, needs mingw-w64):
cargo build --release --target x86_64-pc-windows-gnu -p ig-cli -p ig-node
```

`just` recipes exist for these steps. Run `just` to list them.

## Quick start

### 1. Lighthouse on the VPS

Open TCP and UDP port 7777 in the firewall. Then:

```sh
sudo install -m 755 target/release/ig-lighthouse /usr/local/bin/
sudo ig-lighthouse serve --public-host lighthouse.example.com
```

A systemd unit is in `deploy/ig-lighthouse.service`. The key and state live in `/var/lib/intergalactic/lighthouse/`.

### 2. Create networks and invites

Run these on the VPS (the admin CLI talks to the daemon over a local socket):

```sh
sudo ig-lighthouse network create dev  10.90.0.0/24 --ipv6 fd42:9a:1::/64
sudo ig-lighthouse network create game 10.91.0.0/24
sudo ig-lighthouse network policy game --allow udp:27015-27030 --allow icmp
sudo ig-lighthouse network relay-limit game --per-node-kbps 2000 --total-kbps 20000
sudo ig-lighthouse device add dev printer 192.168.1.50      # reachable via any `--gateway` node on 192.168.1.0/24
sudo ig-lighthouse invite create dev --uses 5 --ttl 7d --label laptops
```

The last command prints an invite string that starts with `ig1:`. The invite contains the lighthouse address and public key, the network id and a one-time secret. The lighthouse stores only a hash of the secret.

### 3. Join from a Linux or Windows machine

```sh
sudo ig-node run            # Linux: needs CAP_NET_ADMIN for the TUN device
sudo ig join ig1:...        # from another terminal
sudo ig status
```

On Windows, run `ig-node.exe run` as Administrator with `wintun.dll` next to the executable, then `ig.exe join ig1:...`. See `docs/deploy.md`.

Each joined network gets its own interface (`ig-dev`, `ig-game`) with the addresses the lighthouse assigned. Peers are reachable by name: `ssh laptop.dev.ig.internal`. Leave with `ig leave dev`.

### 4. Android

Build the Rust core with `android/build-rust.sh` (needs the Android NDK and `cargo-ndk`), then open `android/` in Android Studio or run `./gradlew assembleDebug`. Paste an invite in the app and press Connect. See `docs/android.md`.

## How it works

See `docs/architecture.md` for the full design. In short:

1. A node authenticates to the lighthouse over a Noise IK channel using its X25519 key. The same key is its WireGuard identity.
2. The lighthouse pushes the member list of each network to every online member: addresses, LAN endpoints and the public address it observed on UDP.
3. Two peers send WireGuard handshakes to each other's candidate endpoints at the same time (hole punching). If that works the path is **direct**. Until then, and if it never works, packets are **relayed** through the lighthouse.
4. Every inbound packet is checked: the source must be the peer's address in a shared network, the destination must be this node's address in that same network, and the network policy must allow the flow.
5. DNS queries for the overlay domain go to a reserved address in each network (`10.90.0.1`). The node answers them itself from the peer list it already has.

## Features

- **IPv4 and IPv6** overlay addresses. Give a network an IPv6 prefix with `--ipv6` and every member gets matching v4 and v6 host numbers. Peers also reach each other over IPv6 underlay endpoints when available.
- **Peer DNS** on a domain you choose (`--dns-domain`, default `ig.internal`). Every member is `<host>.<network>.<domain>`, plus the shortcut `<host>.<domain>`. Names are answered inside the tunnel by the node itself, so no DNS server is exposed anywhere.
- **Windows service**: `ig-node service install` registers the daemon with the Service Control Manager and starts it at boot.
- **Relay rate limits** per network (per member and total), with a lighthouse-wide default. Direct peer-to-peer traffic is never limited.
- **Policies** per network: allow lists of inbound flows, stateful, so an untrusted network can be restricted to a game's ports.
- **Gateway devices**: register a printer, NAS or any machine on a physical LAN and members reach it at an overlay address and name. Nodes started with `--gateway` on that LAN forward and translate for it; the lighthouse picks one and fails over within a minute when it leaves.

## Verification

`cargo test` covers the protocol and the engine with in-memory TUN devices over loopback.
`lab/` holds vmlab labs that run the real binaries on QEMU/KVM guests: Ubuntu and Windows
Server nodes with real TUN/Wintun devices, the OS resolvers, the Windows service, hole
punching through two netfilter NATs, and the Android app on an emulator. See
`lab/README.md` for what each lab checks and the results.

## Status and limits

- The Android app has been verified on an emulator (see `lab/README.md`), not yet on a physical phone.
- The lighthouse itself must be reachable over IPv4 or IPv6 from every member. Members on IPv4-only networks can still talk to IPv6 members through the lighthouse relay.
- Hostnames that collide inside one network get a numeric suffix (`laptop`, `laptop-2`).
