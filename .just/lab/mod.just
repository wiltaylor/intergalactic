set working-directory := '../..'

import '../shared.just'

[default, private]
main:
	@just --list lab

[private]
require-vmlab:
	@command -v vmlab > /dev/null 2>&1 || (echo "vmlab is required: curl -fsSL https://vmlab.io/install.sh | sh -s -- --pre" && exit 1)

# Build the static Linux and Windows guest binaries into lab/bin (wintun.dll is not included)
[group('lab')]
bins: require-cargo
	CC_x86_64_unknown_linux_musl=gcc cargo build --release --target x86_64-unknown-linux-musl -p ig-node -p ig-cli -p ig-lighthouse
	cargo build --release --target x86_64-pc-windows-gnu -p ig-node -p ig-cli
	mkdir -p lab/bin
	cp target/x86_64-unknown-linux-musl/release/ig target/x86_64-unknown-linux-musl/release/ig-node target/x86_64-unknown-linux-musl/release/ig-lighthouse lab/bin/
	cp target/x86_64-pc-windows-gnu/release/ig.exe target/x86_64-pc-windows-gnu/release/ig-node.exe lab/bin/

# Bring the flat lab up (lighthouse, two Linux nodes, one Windows node)
[group('lab')]
flat-up: require-vmlab
	cd lab/flat && vmlab up

# Run the Linux scenario against the flat lab
[group('lab')]
flat-linux: require-vmlab
	cd lab/flat && vmlab script scripts/linux.ws

# Run the Windows service scenario against the flat lab (after flat-linux)
[group('lab')]
flat-windows: require-vmlab
	cd lab/flat && vmlab script scripts/windows.ws

# Run both flat scenarios
[group('lab')]
flat-test: flat-linux flat-windows

# Stop the flat lab, keeping the clones
[group('lab')]
flat-down: require-vmlab
	cd lab/flat && vmlab down

# Run the NAT scenario (host lighthouse, two NAT'd nodes)
[group('lab')]
nat-test: require-vmlab
	./lab/nat/run.sh

# Stop the NAT lab and the host lighthouse
[group('lab')]
nat-down: require-vmlab
	cd lab/nat && vmlab down
	pkill -f 'ig-lighthouse --state-dir .lh' || true
