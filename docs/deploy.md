# Deployment

## Lighthouse (Linux VPS)

1. Build or download `ig-lighthouse`, copy it to `/usr/local/bin/`.
2. Open TCP **and** UDP 7777 (or the port you choose).
3. Install `deploy/ig-lighthouse.service`, set `--public-host` to the public DNS name or IP:

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

### Policies

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

The lighthouse has the public address, so it can publish ports for members: the developer
who needs a webhook to reach a dev server, or a home server that must be reachable from the
internet.

```sh
# Ephemeral, from the node, gone when the node disconnects:
ig expose 8080                        # tcp://lighthouse.example.com:20017 -> 127.0.0.1:8080
ig expose 27015 --udp --public-port 20500
ig expose 192.168.1.50:80 --label nas  # anything this node can reach, gateway devices included
ig exposes
ig unexpose <id>

# Permanent, by the admin, persisted on the lighthouse:
sudo ig-lighthouse forward add dev <node-id> 20022 127.0.0.1:22 --label ssh
sudo ig-lighthouse forward add dev <node-id> 443 127.0.0.1:8443
sudo ig-lighthouse forward list
sudo ig-lighthouse forward remove <id>

# Keep untrusted networks from publishing anything:
sudo ig-lighthouse network expose game --deny
```

Ephemeral ports come from `serve --forward-range 20000-20999` (default); open that range
in the VPS firewall, plus any permanent ports. `--forward-range none` disables ephemeral
forwards for the whole lighthouse. Each node may hold eight ephemeral forwards at a time.

Bytes travel over a second encrypted connection from the node to the lighthouse, the tunnel
channel, so a forward works for any member, including nodes behind NATs that never get a
direct path. The service on the node sees connections coming from `127.0.0.1`; the
lighthouse logs the real client address.

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

The device gets an overlay address from the network and a name (`printer.dev.ig.internal`).
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
