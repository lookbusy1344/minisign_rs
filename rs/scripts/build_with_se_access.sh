#!/bin/bash
# Build minisign_rs with Secure Enclave access via Xcode wrapper
#
# Prerequisites:
# 1. Xcode project created (see docs/secure-enclave-xcode-setup.md)
# 2. Xcode configured with your free Apple ID
# 3. Automatic signing enabled with keychain entitlement

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WRAPPER_DIR="$PROJECT_DIR/xcode_wrapper"

echo "=== Building minisign_rs with Secure Enclave Access ==="
echo ""

# Step 1: Build Rust binary
echo "[1/3] Building Rust binary with Secure Enclave support..."
cd "$PROJECT_DIR"
cargo build --release --features hw-keystore-macos
echo "✅ Rust binary built"
echo ""

# Step 2: Build Xcode wrapper
echo "[2/3] Building Xcode wrapper (embeds provisioning profile)..."
if [ ! -d "$WRAPPER_DIR/minisign_wrapper.xcodeproj" ]; then
    echo "❌ Xcode project not found at: $WRAPPER_DIR"
    echo ""
    echo "Please create the Xcode wrapper project first:"
    echo "  1. Open Xcode"
    echo "  2. File > New > Project > macOS > Command Line Tool"
    echo "  3. Save in: $WRAPPER_DIR"
    echo "  4. Enable automatic signing with your Apple ID"
    echo "  5. Add Keychain Sharing capability"
    echo ""
    echo "See: docs/secure-enclave-xcode-setup.md"
    exit 1
fi

cd "$WRAPPER_DIR"
xcodebuild -project minisign_wrapper.xcodeproj \
           -scheme minisign_wrapper \
           -configuration Release \
           build

BUILT_BINARY=$(find ~/Library/Developer/Xcode/DerivedData -name "minisign_wrapper" -type f -perm +111 | grep Release | head -1)
echo "✅ Xcode wrapper built: $BUILT_BINARY"
echo ""

# Step 3: Create convenient symlink
echo "[3/3] Creating symlink..."
ln -sf "$BUILT_BINARY" "$PROJECT_DIR/minisign_rs_se"
echo "✅ Symlink created: $PROJECT_DIR/minisign_rs_se"
echo ""

echo "=== Build Complete ==="
echo ""
echo "Usage:"
echo "  ./minisign_rs_se -G --hardware-key -s test.key -p test.pub"
echo ""
echo "This will trigger Touch ID for Secure Enclave access!"
