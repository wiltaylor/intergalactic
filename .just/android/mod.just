set working-directory := '../..'

import '../shared.just'

[default, private]
main:
	@just --list android

# Build libig_mobile.so for arm64-v8a and x86_64 and generate the Kotlin bindings
[group('android')]
core-build: require-cargo require-cargo-ndk
	android/build-rust.sh

# Assemble the debug APK (runs core-build first)
[group('android')]
apk-build: core-build
	cd android && ./gradlew assembleDebug

# Install the debug APK on the connected device
[group('android')]
apk-install: apk-build
	cd android && ./gradlew installDebug
