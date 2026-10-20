# Intergalactic: overlay networks with a self-hosted lighthouse.

# Verification gate
mod ci '.just/ci'

# Android app and Rust core for Android
mod android '.just/android'

# vmlab virtual labs for real-machine verification
mod lab '.just/lab'

import '.just/shared.just'

[default, private]
main:
	@just --list

# Build every desktop binary (ig, ig-node, ig-lighthouse) in release mode
[group('build')]
build: require-cargo
	cargo build --release -p ig-cli -p ig-node -p ig-lighthouse

# Cross-compile the desktop binaries for Windows (needs x86_64-w64-mingw32-gcc)
[group('build')]
build-windows: require-cargo
	cargo build --release --target x86_64-pc-windows-gnu -p ig-cli -p ig-node -p ig-lighthouse

# Run the whole test suite
[group('test')]
test: require-cargo
	cargo test --workspace

# Run a lighthouse on loopback for local experiments (state in ./tmp/lh)
[group('dev')]
lighthouse-dev: require-cargo
	mkdir -p tmp/lh
	RUST_LOG=info cargo run -p ig-lighthouse -- --state-dir tmp/lh --admin-socket tmp/lh.sock serve --listen 127.0.0.1:7777 --public-host 127.0.0.1

# Run a node daemon against the dev lighthouse (needs root for the TUN device)
[group('dev')]
node-dev: require-cargo
	mkdir -p tmp/node
	RUST_LOG=info cargo run -p ig-node -- --state-dir tmp/node --socket tmp/node.sock run
