# Deployment

## Lighthouse (Linux VPS)

1. Build or download `ig-lighthouse`, copy it to `/usr/local/bin/`.
2. Open TCP **and** UDP 7777 (or the port you choose).
3. Install `nftables` (the `nft` binary) if public forwards are wanted.
4. Install `deploy/ig-lighthouse.service`, set `--public-host` to the public DNS name or IP
   and `--name` to the name members will see (`lh.dev.ig.internal`):

```sh
sudo cp deploy/ig-lighthouse.service /etc/systemd/system/
sudo systemctl enable --now ig-lighthouse
sudo journalctl -u ig-lighthouse -f
```

Admin commands need access to `/var/lib/intergalactic/lighthouse/admin.sock`:

```sh
sudo ig-lighthouse info
sudo ig-lighthouse network create dev 10.90.0.0/24 --ipv6 fd42:9a:1::/64
sudo ig-lighthouse invite create dev --uses 10 --ttl 30d --label "team"
sudo ig-lighthouse node list
sudo ig-lighthouse node remove dev <node-id>
```

Pick non-overlapping CIDRs for networks a single device may join. Each network needs a prefix
of /30 or larger.

The lighthouse joins every network it creates. It takes the second address (`10.90.0.2`), owns
a TUN device `ig-<network>` and answers to `<name>.<network>.<domain>` like any member. The
unit runs as root with `CAP_NET_ADMIN`, because the TUN device and the forward NAT rules need
it. Pass `--no-overlay` for a coordination-only lighthouse without a TUN device; public
forwards are then unavailable on that lighthouse.

### Second lighthouse

Two lighthouses serve the same networks as equals: there is no primary. Each holds the whole
store, accepts joins and admin changes on its own, publishes its own forwards, and the two
merge whenever they are connected. A typical pair is one VPS and one machine at home behind
a forwarded port; nodes connect to both, so a member keeps working when either is down.

```sh
# On each lighthouse: print its public key.
sudo ig-lighthouse info

# On the second machine, start a lighthouse of its own:
sudo ig-lighthouse serve --public-host home.example.com --name home --dns-domain ig.internal

# Register each on the other (name, host, port, key):
sudo ig-lighthouse lighthouse add home home.example.com 7777 <home-key>      # on the VPS
sudo ig-lighthouse lighthouse add vps  lighthouse.example.com 7777 <vps-key>  # at home
sudo ig-lighthouse lighthouse list                                           # LINK up on both
```

The two link up, exchange their stores and from then on push every change to each other.
Online nodes learn the second lighthouse on the next push and connect to it. New invites name
both lighthouses; a node that holds an old invite learns the second one after its first join.

What happens when they are apart:

- Each lighthouse hands out addresses from its own part of every network's pool, so joins
  on both sides do not collide. Should they ever collide, the lighthouses move the newer
  record to a free address and agree on the result.
- An invite counts its uses per lighthouse. Two lighthouses can together hand out more joins
  than the invite allows, by at most one per lighthouse.
- For the same record changed on both sides, the newer change wins. A device registered under
  one name on both sides keeps the newer registration.
- Deleting something on one side deletes it everywhere once they meet again, even if the other
  side still shows it.

Settings given on the command line (`--dns-domain`, `--relay-limit-*`, `--forward-range`)
belong to each lighthouse and are not replicated, so give both the same values.
`lighthouse remove <key>` on either side evicts a lighthouse from the pair; add it again to
let it back in.

## Policies

```sh
# Only let members accept SSH and ping. Everything a member opens itself still works.
sudo ig-lighthouse network policy dev --allow tcp:22 --allow icmp
# Game servers on 27015-27030 plus Steam voice.
sudo ig-lighthouse network policy game --allow udp:27015-27030 --allow tcp:27015-27030
# Back to allow-all:
sudo ig-lighthouse network policy dev
```

Policy changes reach online members within a second.

### DNS domain

`ig-lighthouse serve --dns-domain ig.internal` sets the suffix for peer names. Use a name
that does not exist on the internet; `.internal` is reserved for exactly this. Members become
`<host>.<network>.<domain>`, for example `laptop.dev.ig.internal`, and the shortcut
`laptop.ig.internal` works when the label is unique across the device's networks.

### Relay limits

```sh
# Default for every network that has no limit of its own:
ig-lighthouse serve ... --relay-limit-per-node-kbps 5000 --relay-limit-total-kbps 50000
# Per network:
sudo ig-lighthouse network relay-limit game --per-node-kbps 1000 --total-kbps 10000
# Back to the lighthouse default:
sudo ig-lighthouse network relay-limit game
```

Limits apply only to traffic relayed through the lighthouse. Direct paths are never limited.

## Public port forwards

A lighthouse has a public address, so it can publish ports for members: the developer who
needs a webhook to reach a dev server, or a home server that must be reachable from the
internet. The public connection is translated into the overlay on the lighthouse, so the
bytes cross the internet only inside WireGuard.

```sh
# Ephemeral, from the node, gone when the node disconnects:
ig expose 8080                        # tcp://lighthouse.example.com:20017 -> this node:8080
ig expose 27015 --udp --public-port 20500
ig expose nas:80 --label nas          # a gateway device of this network
ig expose 8080 --lighthouse lh2       # publish on a specific lighthouse
ig exposes
ig unexpose <id>

# Permanent, by the admin, persisted on the lighthouse:
sudo ig-lighthouse forward add dev <node-id> 20022 self:22 --label ssh
sudo ig-lighthouse forward add dev <node-id> 443 self:8443 --lighthouse lh2
sudo ig-lighthouse forward add dev <node-id> 8080 nas:80
sudo ig-lighthouse forward list
sudo ig-lighthouse forward remove <id>

# Keep untrusted networks from publishing anything:
sudo ig-lighthouse network expose game --deny
```

A target is `self:PORT` (the node's own overlay address), `<device>:PORT` (a gateway device
of the network) or `<overlay-ip>:PORT`. The service must listen on the overlay address, not
only on `127.0.0.1`.

Ephemeral ports come from `serve --forward-range 20000-20999` (default); open that range in
the VPS firewall, plus any permanent ports. `--forward-range none` disables ephemeral
forwards for the whole lighthouse. Each node may hold eight ephemeral forwards at a time.

The lighthouse installs the forwards as nftables rules in the tables `ig_forwards` (`ip` and
`ip6`): a destination NAT from the public port to the overlay target and a masquerade on its
`ig-*` interfaces. The node sees connections coming from the lighthouse's overlay address.
A forward works for any member, including nodes behind NATs that never get a direct path,
because the lighthouse reaches them over the relay.

## Gateway devices

A device that cannot run Intergalactic (a printer, a NAS, a lab box) can still be a member
of a network through one or more **gateway nodes** on its LAN.

```sh
# On the nodes that sit on the device's LAN (Linux or Windows):
sudo ig-node run --gateway            # or: ig-node.exe service install --gateway
# On the lighthouse:
sudo ig-lighthouse device add dev printer 192.168.1.50
sudo ig-lighthouse device add dev nas 192.168.1.60 --ipv6 fd00:1::60 --via <node-id-a> --via <node-id-b>
sudo ig-lighthouse device list dev
```

A physical address can be registered once per network. The device gets an overlay address from the network and a name (`printer.dev.ig.internal`).
With `--ipv6` it also gets an overlay IPv6 address (same host number, in the network's IPv6
prefix) and an AAAA record; the network must have been created with `--ipv6`.
Without `--via`, any online `--gateway` member whose LAN contains the device's address can
serve it; with `--via`, only the listed nodes, in that order. The lighthouse keeps the current
gateway while it qualifies and switches when it disconnects, stops reporting that LAN, or is
removed. A node that vanishes without closing its connection is noticed within 45 seconds.

On the gateway, the engine rewrites the device's overlay address to its physical address and
the kernel forwards the packet with source NAT onto the LAN. Linux: `ip_forward` plus an
nftables tables `ig_gateway` in the `ip` and `ip6` families (masquerade, and an output DNAT
so the gateway reaches its own devices too). Windows: IP forwarding plus a `NetNat` for the
overlay prefix; Windows NAT is IPv4 only and the local hairpin is not available there, so a
Windows gateway serves IPv4 devices to other members only. Network policies apply to device
traffic the same way they apply to the gateway itself. Android nodes cannot be gateways.

## Node on Linux

```sh
sudo install -m 755 target/release/ig-node target/release/ig /usr/local/bin/
sudo cp deploy/ig-node.service /etc/systemd/system/
sudo systemctl enable --now ig-node
sudo ig join ig1:...
sudo ig status
```

The daemon needs `CAP_NET_ADMIN` for `/dev/net/tun`. The control socket is
`/run/intergalactic/node.sock` (mode 0660), so `ig` needs root or the same group.

Useful flags for `ig-node run`: `--port 41641` to pin the UDP port (then forward it on your
router for the best chance of direct paths), `--relay-only` to force relaying,
`--hostname` to override the name shown to peers, `--dns auto|system|hosts|off` to choose how
peer names are made resolvable (`auto` uses systemd-resolved when present, otherwise the
hosts file).

## Node on Windows

1. Download `wintun.dll` from <https://www.wintun.net/> and place it next to `ig-node.exe`,
   for example in `C:\Program Files\Intergalactic\`.
2. From an **Administrator** prompt install the service:

   ```powershell
   ig-node.exe service install            # registers "ig-node", starts it, starts at boot
   ig.exe join ig1:...
   ig.exe status
   ```

   `service install` accepts the same flags as `run` (`--port`, `--dns`, `--relay-only`,
   `--hostname`). The service logs to `C:\ProgramData\Intergalactic\node\ig-node.log`.
   `ig-node.exe service stop|start|uninstall` manage it afterwards.
3. To run in the foreground instead: `ig-node.exe run`.

Peer names are made resolvable with Name Resolution Policy Table rules, so only
`*.ig.internal` queries go to the overlay. The daemon also adds one inbound Windows Firewall
rule per overlay interface (group "Intergalactic"), because Windows treats a new adapter as a
public network and would otherwise drop every unsolicited packet, ping included. Network
policies remain the access control. `service uninstall`, `ig leave` and a clean stop remove
the rules they added.

`ig-node.exe service stop` waits until the service has stopped, so `stop` followed by
`start` is safe.

## Containers and ephemeral environments

Each container can run `ig-node` with its own state directory and join a network with a
multi-use invite. Give the container `CAP_NET_ADMIN` and `/dev/net/tun`:

```sh
docker run --cap-add NET_ADMIN --device /dev/net/tun \
  -v ig-state:/var/lib/intergalactic/node myimage \
  sh -c 'ig-node run & sleep 1; ig join "$INVITE"; wait'
```

When the container is destroyed, remove it from the lighthouse with `node remove`, or create
a dedicated short-lived network and delete the whole network afterwards.

## Troubleshooting

- `ig status` shows `relay` for a peer: both sides are behind NATs that defeat hole punching.
  Pin a UDP port on one side and forward it, or accept relayed traffic.
- `lighthouse_connected: false`: check that TCP 7777 reaches the lighthouse and that the
  invite's host resolves. `RUST_LOG=debug ig-node run` shows the reason.
- No interface created: on Linux check `CAP_NET_ADMIN`; on Windows check `wintun.dll` and
  Administrator rights.
- `lighthouse list` shows a peer `down`: check TCP 7777 between the two lighthouses in both
  directions; each one dials the other. Nodes keep working in the meantime.
- A forward does not answer: check that `nft list table ip ig_forwards` on the lighthouse
  lists the port, that the service on the node listens on the overlay address, and that the
  network policy allows the port from the lighthouse's overlay address.
