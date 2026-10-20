# Helpers shared by the top-level justfile and the modules.

[private]
require-cargo:
	@command -v cargo > /dev/null 2>&1 || (echo "cargo is required (https://rustup.rs)" && exit 1)

[private]
require-cargo-ndk:
	@command -v cargo-ndk > /dev/null 2>&1 || (echo "cargo-ndk is required: cargo install cargo-ndk" && exit 1)
	@test -n "${ANDROID_NDK_HOME:-}" || (echo "ANDROID_NDK_HOME must point at an Android NDK" && exit 1)

# Check formatting without modifying files
[group('quality')]
fmt-check: require-cargo
	cargo fmt --all --check

# Format the workspace
[group('quality')]
fmt: require-cargo
	cargo fmt --all
