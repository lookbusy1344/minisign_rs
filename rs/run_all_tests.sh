#!/usr/bin/env bash
#
# Run all tests for minisign-rs
#
# Usage:
#   ./run_all_tests.sh                          # All tests (default, no keychain popups)
#   ./run_all_tests.sh --credential-store       # Credential store tests only (requires user interaction)
#   ./run_all_tests.sh --all                    # All tests including credential store
#
# Test categories:
#   - Default tests: Full suite including production-strength scrypt and C compatibility
#                    tests (C tests skip with a warning if minisign is not installed)
#   - Credential store tests: Tests requiring OS keyring authorization (macOS Keychain, etc.)
#
# Note: Default tests run with --no-default-features to disable the credential_store
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
        echo "Running tests (without credential store)..."
        gtimeout 120 cargo test --no-default-features
        echo ""
        echo "✓ Tests completed successfully!"
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
        echo "Running tests (without credential store)..."
        gtimeout 120 cargo test --no-default-features
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
