#!/usr/bin/env bash
# Start a lighthouse on the host, bring the NAT lab up and run the scenario.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
LH_BIN="$ROOT/target/release/ig-lighthouse"
HOST_IP="${IG_LH_HOST:-$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')}"
PORT=17777
pkill -f "ig-lighthouse --state-dir .lh" || true
sleep 0.5
rm -rf .lh .lh.sock
mkdir -p .lh
RUST_LOG=info "$LH_BIN" --state-dir .lh --admin-socket .lh.sock serve --listen "0.0.0.0:$PORT" --public-host "$HOST_IP" --dns-domain ig.test > .lh/lighthouse.log 2>&1 &
sleep 1
ADMIN="$LH_BIN --state-dir .lh --admin-socket .lh.sock"
$ADMIN network create dev 10.90.0.0/24 --ipv6 fd42:9a:1::/64 > /dev/null
INVITE=$($ADMIN invite create dev --uses 10 --ttl 2h 2>/dev/null | sed 's/^ig join //')
echo "lighthouse on $HOST_IP:$PORT, invite created"
sed "s|@INVITE@|$INVITE|g" scripts/nat.ws.in > scripts/nat.ws
vmlab validate
vmlab up
vmlab script scripts/nat.ws
echo "--- lighthouse view ---"
$ADMIN node list
