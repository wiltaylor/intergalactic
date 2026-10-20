#!/usr/bin/env bash
# Build the Rust core for Android and generate the Kotlin bindings.
# Requires: Android NDK (ANDROID_NDK_HOME), `cargo install cargo-ndk`,
#           `rustup target add aarch64-linux-android x86_64-linux-android`.
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-release}"
TARGETS=(arm64-v8a x86_64)

args=()
for t in "${TARGETS[@]}"; do args+=(-t "$t"); done
cargo ndk "${args[@]}" -o android/app/src/main/jniLibs build --profile "$PROFILE" -p ig-mobile

# Any one of the built libraries works as the metadata source for bindgen.
lib="$(find target -path "*linux-android/$PROFILE/libig_mobile.so" | head -1)"
if [ "$PROFILE" = "dev" ]; then lib="$(find target -path "*linux-android/debug/libig_mobile.so" | head -1)"; fi
cargo run -q -p ig-mobile --features bindgen --bin uniffi-bindgen -- \
  generate --library "$lib" --language kotlin --no-format \
  --out-dir android/app/src/main/generated
echo "ok: native libs in android/app/src/main/jniLibs, bindings in android/app/src/main/generated"
