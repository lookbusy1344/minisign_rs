#!/bin/bash
# Sign minisign_rs binary for Secure Enclave access
#
# Usage: ./scripts/sign_for_secure_enclave.sh [identity]
#
# If no identity provided, will list available identities

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/minisign_rs"
ENTITLEMENTS="$PROJECT_DIR/entitlements.plist"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY"
    echo "Build with: cargo build --release --features hw-keystore-macos"
    exit 1
fi

# Check if entitlements file exists
if [ ! -f "$ENTITLEMENTS" ]; then
    echo "Error: Entitlements file not found at $ENTITLEMENTS"
    exit 1
fi

# If no identity provided, list available identities
if [ $# -eq 0 ]; then
    echo "=== Available Signing Identities ==="
    echo ""
    security find-identity -v -p codesigning 2>/dev/null | grep -v "0 valid identities found" || true
    echo ""
    echo "=== Usage ==="
    echo "1. Pick an identity from the list above"
    echo "2. Run: $0 \"Identity Name\""
    echo ""
    echo "Examples:"
    echo "  $0 \"Apple Development: your@email.com\""
    echo "  $0 \"Apple Development: your@email.com (TEAM123456)\""
    echo ""
    echo "If you don't have any identities:"
    echo "  1. Open Xcode"
    echo "  2. Preferences > Accounts"
    echo "  3. Add your Apple ID (free account works)"
    echo "  4. Select your account > Manage Certificates > + > Apple Development"
    exit 0
fi

IDENTITY="$1"

echo "=== Signing minisign_rs for Secure Enclave Access ==="
echo "Binary:       $BINARY"
echo "Entitlements: $ENTITLEMENTS"
echo "Identity:     $IDENTITY"
echo ""

# Sign the binary
if codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" "$BINARY"; then
    echo ""
    echo "✅ Successfully signed!"
    echo ""
    echo "=== Verification ==="
    codesign -dv "$BINARY" 2>&1 | head -10
    echo ""
    echo "=== Testing Secure Enclave ==="
    echo "Run: ./target/release/minisign_rs -G --hardware-key -s test.key -p test.pub"
    echo ""
    echo "This will trigger a Touch ID prompt if Secure Enclave is available."
else
    echo ""
    echo "❌ Signing failed!"
    echo ""
    echo "Common issues:"
    echo "  1. Identity not found - check available identities with: $0"
    echo "  2. Certificate expired - generate new one in Xcode"
    echo "  3. Wrong identity name - use exact name from the list"
    exit 1
fi
