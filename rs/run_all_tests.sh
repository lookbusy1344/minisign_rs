#!/usr/bin/env bash
#
# Run all tests for minisign-rs
#
# Usage:
#   ./run_all_tests.sh                          # Fast + slow tests (default, no keychain popups)
#   ./run_all_tests.sh --credential-store       # Credential store tests only (requires user interaction)
#   ./run_all_tests.sh --all                    # All tests including credential store
#
# Test categories:
#   - Fast tests: Default test suite (~9s, N=2^14 for scrypt)
#   - Slow tests: Security tests with production KDF params (~16s, N=2^20 for scrypt)
#   - Credential store tests: Tests requiring OS keyring authorization (macOS Keychain, etc.)
#
# Note: Fast and slow tests run with --no-default-features to disable credential_store
#       feature, preventing keychain popup dialogs during development.
#       Credential store tests explicitly enable the feature and credential_store_tests.
#
set -e

# Parse command line arguments
RUN_MODE="default"
if [[ "$1" == "--credential-store" ]]; then
    RUN_MODE="credential-store"
elif [[ "$1" == "--all" ]]; then
    RUN_MODE="all"
fi

case "$RUN_MODE" in
    "default")
        echo "Running fast tests (without credential store)..."
        gtimeout 120 cargo test --no-default-features
        echo ""
        echo "Running slow tests (without credential store)..."
        gtimeout 300 cargo test --no-default-features -- --ignored
        echo ""
        echo "✓ Fast and slow tests completed successfully!"
        ;;

    "credential-store")
        echo "Running credential store tests..."
        echo "Note: These tests require OS keyring authorization."
        echo "      You may be prompted multiple times by macOS Keychain."
        echo "      Click 'Always Allow' to reduce prompts."
        echo ""
        gtimeout 180 cargo test --features credential_store_tests -- --test-threads=1
        echo ""
        echo "✓ Credential store tests completed successfully!"
        ;;

    "all")
        echo "Running fast tests (without credential store)..."
        gtimeout 120 cargo test --no-default-features
        echo ""
        echo "Running slow tests (without credential store)..."
        gtimeout 300 cargo test --no-default-features -- --ignored
        echo ""
        echo "Running credential store tests..."
        echo "Note: These tests require OS keyring authorization."
        echo "      You may be prompted multiple times by macOS Keychain."
        echo "      Click 'Always Allow' to reduce prompts."
        echo ""
        gtimeout 180 cargo test --features credential_store_tests -- --test-threads=1
        echo ""
        echo "✓ All tests completed successfully!"
        ;;
esac
