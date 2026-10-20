# Architecture

## Identities

Every node and every lighthouse has one X25519 key pair. The public key is the identity.
A node uses the same key for two purposes:

- the Noise IK handshake with the lighthouse (control plane),
- WireGuard sessions with peers (data plane).

Because the lighthouse learns a node's public key from the authenticated Noise handshake,
and shares exactly that key with the other members, a peer cannot be impersonated.

## Control plane: node to lighthouse

TCP, framed Noise `Noise_IK_25519_ChaChaPoly_BLAKE2s`. The node knows the lighthouse key from the invite.
Messages are `postcard` encoded enums (`ig_proto::control`). Large messages are split across
Noise transport messages so peer lists of any size fit.

| Direction | Message | Purpose |
| --- | --- | --- |
| node → LH | `Join {network, token}` | Consume an invite, get an address |
| node → LH | `Leave`, `Resume` | Leave, or ask for all memberships after reconnect |
| node → LH | `Endpoints {local}` | LAN candidate endpoints |
| node → LH | `Punch {network, target}` | Ask the target to send towards us |
| LH → node | `NetworkState {network, peers}` | Full membership of a network. Pushed on every change |
| LH → node | `PunchRequest {from, endpoints}` | A peer wants to reach us |
| LH → node | `Removed` | Admin removed us or deleted the network |

The lighthouse coalesces changes for 150 ms and then pushes `NetworkState` to every online member.

## UDP: disco and relay

The node has one UDP socket for everything. Datagrams that start with `IGD\x01` are disco
frames (`ig_proto::disco`). Everything else is WireGuard.

- `Probe` (node → LH): tells the lighthouse the node's public address. Authenticated with a
  MAC keyed by the per-session token, so an attacker cannot poison it. Sent every 20 s, which
  also keeps the NAT mapping open.
- `ProbeReply` (LH → node): the observed address.
- `Relay {dst, payload}` (node → LH) and `Relayed {src, payload}` (LH → node): the lighthouse
  forwards a WireGuard datagram to `dst` if the sender's address is a probed node and the two
  nodes share a network. The payload is end-to-end encrypted. The lighthouse cannot read it.

## Data plane

`boringtun` provides one `Tunn` (WireGuard state machine) per peer. The engine:

1. Reads an IP packet from a TUN device, looks up the destination address in the route table
   (address → peer), checks the source is our address in that same network, and encapsulates.
2. Sends the result along the peer's best path:
   - **direct**: the endpoint we last received authenticated traffic from;
   - otherwise **relay** through the lighthouse, plus a punch attempt at most every 5 s:
     send the packet to every candidate endpoint and ask the lighthouse to make the peer
     send towards us.
3. On receive, identifies the peer (handshake initiations by parsing the static key, everything
   else by session index), decapsulates, and marks the path direct if the datagram arrived
   directly. A direct path that stays silent for 30 s while we keep sending falls back to relay.
4. Validates the decrypted packet (see Security) and writes it to the TUN for that network.

### TUN layout

- Linux and Windows: one TUN per network, named `ig-<network>`, with the assigned address
  and prefix. The kernel routes the network's CIDR into it.
- Android: `VpnService` allows one TUN per app. The engine attaches it with `TunScope::All`
  and demultiplexes by address. The app adds one address and one route per network.

## Networks and isolation

Networks are independent address spaces. A node in `dev` and `game` has two addresses and two
interfaces. A peer only in `game` only learns the node's `game` address.

Isolation is enforced at the receiver, not only by routing:

- the decrypted packet's source must equal the peer's address in some shared network `N`;
- the destination must equal our own address in `N`;
- the policy of `N` must allow the flow.

So a device in `game` cannot reach a `dev` address even if it crafts packets by hand.

## Policy

A network policy is an allow list of inbound flows (`tcp:22,80`, `udp:27015-27030`, `icmp`).
Empty means allow all. `ig_core::filter` is stateful per peer:

- flows we open are tracked, so replies always pass;
- a TCP flow may only start with a bare SYN that matches a rule;
- stray TCP segments without state are dropped, so the kernel never answers with RST;
- ICMP echo requests need an `icmp` rule; echo replies to our own pings pass; ICMP errors pass.

## Persistence

- Lighthouse: `lighthouse.key` and `lighthouse.json` (networks, members, invite hashes) in the
  state directory. Written atomically on every change.
- Node: `node.json` (private key and memberships). The daemon rewrites it on every
  `MembershipsChanged` event. On start the node resumes all memberships.
- Android: the same JSON, stored in the app's private files directory.

## Threat notes

- An attacker with the lighthouse state file gets invite hashes, not invites.
- A compromised lighthouse can add members to a network (it is the authority on membership),
  but it cannot read or inject traffic between existing peers.
- Nodes pin the lighthouse key from the invite. A fake lighthouse cannot complete the handshake.
