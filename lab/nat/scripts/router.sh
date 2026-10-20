#!/bin/sh
# Turn this Ubuntu VM into a masquerading router.
# $1 = our LAN gateway address, $2 = the WAN address to put on the second NIC.
set -e
LAN="$1"; WANIP="$2"
sysctl -q -w net.ipv4.ip_forward=1
# cloud-init only configures the first NIC; bring the second one up by hand.
WAN=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | while read i; do ip -o -4 addr show dev "$i" | grep -q . || echo "$i"; done | head -1)
if [ -z "$WAN" ]; then WAN=$(ip -o -4 addr show | awk '/10\.99\.0\./{print $2}' | head -1); fi
[ -n "$WAN" ] || { echo "no WAN interface" >&2; exit 1; }
ip link set "$WAN" up
ip -o -4 addr show dev "$WAN" | grep -q "$WANIP" || ip addr add "$WANIP/24" dev "$WAN"
nft flush ruleset
nft add table ip nat
nft 'add chain ip nat post { type nat hook postrouting priority 100 ; }'
nft add rule ip nat post oifname "$WAN" masquerade
# A home-router style firewall: nothing unsolicited comes in from the WAN.
# Unsolicited packets are dropped before conntrack confirms them, so a punch
# that arrives early cannot occupy a port mapping.
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0 ; policy drop ; }'
nft add rule inet filter input iifname != "$WAN" accept
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input icmp type echo-request accept
nft 'add chain inet filter forward { type filter hook forward priority 0 ; policy drop ; }'
nft add rule inet filter forward iifname != "$WAN" accept
nft add rule inet filter forward ct state established,related accept
# The LAN's DHCP default route points at ourselves; drop it.
ip route del default via "$LAN" 2>/dev/null || true
echo "nat on $WAN ($WANIP) for $LAN"
