set working-directory := '../..'

import '../shared.just'

[default, private]
main:
	@just --list ci

# Everything a change must pass before it can merge
[group('ci')]
check: fmt-check lint test

# Lint the workspace, warnings are errors
[group('ci')]
lint: require-cargo
	cargo clippy --workspace --all-targets -- -D warnings

# Run the test suite (unit tests plus loopback end-to-end tests)
[group('ci')]
test: require-cargo
	cargo test --workspace
