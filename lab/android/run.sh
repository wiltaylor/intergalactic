#!/usr/bin/env bash
# Android emulator end-to-end: host lighthouse, one vmlab node, the app on an
# x86_64 emulator. Needs ANDROID_HOME with emulator + system image, a built
# debug APK, and vmlab. The emulator reaches the host at 10.0.2.2.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
LH_BIN="$ROOT/target/release/ig-lighthouse"
HOST_IP="${IG_LH_HOST:-$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')}"
PORT=17777
APK="$ROOT/android/app/build/outputs/apk/debug/app-debug.apk"
PKG=dev.intergalactic.app
AVD="${IG_AVD:-ig}"

pkill -x ig-lighthouse || true
sleep 0.5
rm -rf .lh .lh.sock; mkdir -p .lh
RUST_LOG=info "$LH_BIN" --state-dir .lh --admin-socket .lh.sock serve --listen "0.0.0.0:$PORT" --public-host "$HOST_IP" --dns-domain ig.test --no-overlay > .lh/lighthouse.log 2>&1 &
sleep 1
ADMIN="$LH_BIN --state-dir .lh --admin-socket .lh.sock"
$ADMIN network create dev 10.90.0.0/24 --ipv6 fd42:9a:1::/64 > /dev/null
# The node uses the host's LAN address; the emulator uses 10.0.2.2 for the same host.
$ADMIN invite create dev --uses 5 --ttl 2h 2>/dev/null | sed 's/^ig join //' > invite.txt
echo "lighthouse on $HOST_IP:$PORT"

vmlab validate
vmlab up
vmlab script scripts/node.ws

# Emulator.
adb start-server > /dev/null
if ! adb devices | grep -q emulator; then
  "$ANDROID_HOME/emulator/emulator" -avd "$AVD" -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect -no-snapshot > .lh/emulator.log 2>&1 &
fi
adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
echo "emulator booted"
adb install -r -g "$APK" > /dev/null
adb shell pm clear $PKG > /dev/null          # forget memberships from earlier runs
adb shell appops set $PKG ACTIVATE_VPN allow
adb logcat -c
# The emulator reaches the host lighthouse as 10.0.2.2: rewrite the invite's host.
EMU_INVITE=$("$ROOT/target/release/ig" invite rehost "$(cat invite.txt)" 10.0.2.2)
adb shell am start -W -n $PKG/.MainActivity --es invite "$EMU_INVITE" --ez connect true > /dev/null
echo "app started; accepting the VPN consent dialog if it appears"
tap_ok() {
  adb shell uiautomator dump /sdcard/ui.xml > /dev/null 2>&1 || return 1
  local b
  # The notification permission prompt ("Allow") comes first on Android 13+, then the VPN consent ("OK").
  b=$(adb shell cat /sdcard/ui.xml | tr '>' '\n' | grep -E 'text="(OK|Allow)"' | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' | head -1 | tr -dc '0-9,[]')
  [ -n "$b" ] || return 1
  local x1 y1 x2 y2
  IFS='[],' read -r _ x1 y1 _ x2 y2 _ <<< "$b"
  adb shell input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 ))
}
# The VPN interface is whichever tunN Android hands out.
for i in $(seq 1 30); do
  if adb shell ip -br addr 2>/dev/null | grep '^tun' | grep -q 10.90.0; then break; fi
  tap_ok || true
  sleep 2
done
adb shell ip -br addr | grep '^tun' | grep 10.90.0
# Addresses are allocated by the lighthouse (it is a member itself): read them.
NODE_IP=$(vmlab exec alpha -- sh -c "ig networks | grep '^dev ' | tr -s ' ' | cut -d' ' -f2 | cut -d/ -f1" | tr -d '\r\n')
NODE_IP6=$(vmlab exec alpha -- sh -c "ig networks | grep '^dev ' | tr -s ' ' | cut -d' ' -f3 | cut -d/ -f1" | tr -d '\r\n')
EMU_IP=$(adb shell ip -br addr | grep '^tun' | grep -o '10\.90\.0\.[0-9]*' | head -1)
echo "node $NODE_IP $NODE_IP6, emulator $EMU_IP"
echo "--- emulator -> node ---"
# The first packets trigger the WireGuard handshake; allow a few seconds.
for i in $(seq 1 20); do adb shell ping -c 1 -W 2 "$NODE_IP" > /dev/null 2>&1 && break; sleep 1; done
adb shell ping -c 3 -W 3 "$NODE_IP"
adb shell ping6 -c 3 -W 3 "$NODE_IP6" || adb shell ping -6 -c 3 "$NODE_IP6"
echo "--- emulator DNS ---"
adb shell ping -c 2 -W 3 alpha.dev.ig.test
# Public names keep resolving with the VPN up: the engine forwards them to the
# underlying network's resolver over a protected socket.
adb shell ping -c 1 -W 5 github.com
echo "--- node -> emulator ---"
vmlab exec alpha -- sh -c "ig peers; ping -c 3 -W 3 $EMU_IP; resolvectl query $EMU_IP"
echo "--- lighthouse ---"
$ADMIN node list
echo "--- app log ---"
adb logcat -d -s intergalactic ig/engine ig/vpn | tail -20
echo "ANDROID OK"
