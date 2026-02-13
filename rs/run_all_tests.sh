#!/usr/bin/env bash
#
# Run all tests for minisign-rs
#
# Usage:
#   ./run_all_tests.sh                          # Fast tests only (default)
#   ./run_all_tests.sh --slow                   # Fast + slow tests
#   ./run_all_tests.sh --credential-store       # Credential store tests only (requires user interaction)
#   ./run_all_tests.sh --all                    # All tests including credential store
#
# Test categories:
#   - Fast tests: Default test suite (~9s, N=2^14 for scrypt)
#   - Slow tests: Security tests with production KDF params (~16s, N=2^20 for scrypt)
#   - Credential store tests: Tests requiring OS keyring authorization (macOS Keychain, etc.)
#
# Credential store tests are separate because:
#   - Require user interaction (keyring authorization prompts)
#   - Must run sequentially (--test-threads=1) to avoid parallel prompts
#   - Are not needed for general development
#
set -e

# Parse command line arguments
RUN_MODE="fast"
if [[ "$1" == "--slow" ]]; then
    RUN_MODE="slow"
elif [[ "$1" == "--credential-store" ]]; then
    RUN_MODE="credential-store"
elif [[ "$1" == "--all" ]]; then
    RUN_MODE="all"
fi

case "$RUN_MODE" in
    "fast")
        echo "Running fast tests..."
        gtimeout 120 cargo test
        echo ""
        echo "✓ Fast tests completed successfully!"
        ;;

    "slow")
        echo "Running fast tests..."
        gtimeout 120 cargo test
        echo ""
        echo "Running slow tests (ignored)..."
        gtimeout 300 cargo test -- --ignored
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
        echo "Running fast tests..."
        gtimeout 120 cargo test
        echo ""
        echo "Running slow tests (ignored)..."
        gtimeout 300 cargo test -- --ignored
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
