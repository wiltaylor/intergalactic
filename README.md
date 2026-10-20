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
sudo ig-lighthouse network create dev  10.90.0.0/24
sudo ig-lighthouse network create game 10.91.0.0/24
sudo ig-lighthouse network policy game --allow udp:27015-27030 --allow icmp
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

Each joined network gets its own interface (`ig-dev`, `ig-game`) with the address the lighthouse assigned. Leave with `ig leave dev`.

### 4. Android

Build the Rust core with `android/build-rust.sh` (needs the Android NDK and `cargo-ndk`), then open `android/` in Android Studio or run `./gradlew assembleDebug`. Paste an invite in the app and press Connect. See `docs/android.md`.

## How it works

See `docs/architecture.md` for the full design. In short:

1. A node authenticates to the lighthouse over a Noise IK channel using its X25519 key. The same key is its WireGuard identity.
2. The lighthouse pushes the member list of each network to every online member: addresses, LAN endpoints and the public address it observed on UDP.
3. Two peers send WireGuard handshakes to each other's candidate endpoints at the same time (hole punching). If that works the path is **direct**. Until then, and if it never works, packets are **relayed** through the lighthouse.
4. Every inbound packet is checked: the source must be the peer's address in a shared network, the destination must be this node's address in that same network, and the network policy must allow the flow.

## Status and limits

This is a working first version. Known limits:

- IPv4 overlay addresses only. Endpoint discovery is IPv4 only.
- No DNS for peer names. `ig status` and the lighthouse's `node list` show hostnames.
- Windows runs as a console program. Use NSSM, WinSW or Task Scheduler to run it at boot.
- Android builds are not verified in this repository because it has no Android NDK. The Kotlin bindings are generated from the Rust code and the app uses those exact signatures.
- Relay traffic is not rate limited per node.
