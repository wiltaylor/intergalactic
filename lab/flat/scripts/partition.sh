#!/bin/sh
# Cut or restore the link between this lighthouse and another one, for the
# peers lab. Usage: partition.sh on <peer-ip> | partition.sh off
set -e
case "$1" in
  on)
    nft add table inet igtest 2>/dev/null || true
    nft add chain inet igtest in '{ type filter hook input priority -10; }' 2>/dev/null || true
    nft add chain inet igtest out '{ type filter hook output priority -10; }' 2>/dev/null || true
    nft flush chain inet igtest in
    nft flush chain inet igtest out
    nft add rule inet igtest in ip saddr "$2" tcp dport 7777 drop
    nft add rule inet igtest in ip saddr "$2" tcp sport 7777 drop
    nft add rule inet igtest out ip daddr "$2" tcp dport 7777 drop
    nft add rule inet igtest out ip daddr "$2" tcp sport 7777 drop
    # Kill the established link now instead of waiting for the idle timeout.
    ss -K dst "$2" dport = 7777 > /dev/null 2>&1 || true
    ss -K dst "$2" sport = 7777 > /dev/null 2>&1 || true
    ;;
  off)
    nft delete table inet igtest 2>/dev/null || true
    ;;
esac
