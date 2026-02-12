#!/usr/bin/env bash
#
# Run all tests for minisign-rs
#
# Usage:
#   ./run_all_tests.sh                      # Skip credential store tests (default)
#   ./run_all_tests.sh --with-credential-store  # Include credential store tests (requires macOS Keychain authorization)
#
# Credential store tests are skipped by default because they require multiple
# macOS Keychain authorization prompts. Run with --with-credential-store only when
# specifically testing credential store functionality.
#
set -e

# Parse command line arguments
RUN_CREDENTIAL_STORE_TESTS=false
if [[ "$1" == "--with-credential-store" ]]; then
    RUN_CREDENTIAL_STORE_TESTS=true
fi

echo "Running regular tests (excluding credential store tests)..."
# Skip all tests that interact with OS credential store (macOS Keychain)
# Patterns: credential_store, save_password, saved_password, forget_password, password_saved
gtimeout 120 cargo test -- \
    --skip credential_store \
    --skip save_password \
    --skip saved_password \
    --skip forget_password \
    --skip password_saved

echo ""
echo "Running slow/ignored tests..."
gtimeout 300 cargo test -- --ignored

if [[ "$RUN_CREDENTIAL_STORE_TESTS" == true ]]; then
    echo ""
    echo "Running credential store tests (will prompt for macOS Keychain authorization)..."
    echo "Note: You may be prompted multiple times. Click 'Always Allow' to reduce prompts."
    gtimeout 120 cargo test credential_store
else
    echo ""
    echo "Skipped credential store tests (use --with-credential-store to include them)"
fi

echo ""
echo "All tests completed successfully!"
