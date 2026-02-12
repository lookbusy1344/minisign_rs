# macOS Secure Enclave Setup

This guide explains how to enable real Secure Enclave support for local development.

## Quick Start

### Option 1: Use Mock KeyStore (No Setup Required)

The mock keystore works perfectly for testing and development:

```bash
# Build and run (uses mock by default)
cargo run --release -- -G --hardware-key -s test.key -p test.pub
```

The mock simulates Secure Enclave behavior and is used by the entire test suite.

### Option 2: Real Secure Enclave (Requires Code Signing)

To use the actual Secure Enclave on your Mac:

#### Step 1: Get a Free Apple ID Certificate

1. Open **Xcode**
2. Go to **Xcode → Settings → Accounts**
3. Click **+** to add your Apple ID (free account works)
4. Select your account → **Manage Certificates**
5. Click **+** → **Apple Development**

#### Step 2: Find Your Signing Identity

```bash
./scripts/sign_for_secure_enclave.sh
```

This will list all available signing identities.

#### Step 3: Update Entitlements

Edit `entitlements.plist` and replace `YOUR_TEAM_ID` with your actual Team ID (shown in the signing identity from Step 2, e.g., `ABC1234567`).

#### Step 4: Build and Sign

```bash
# Build with Secure Enclave support
cargo build --release --features hw-keystore-macos

# Sign the binary (use exact identity name from Step 2)
./scripts/sign_for_secure_enclave.sh "Apple Development: your@email.com"
```

#### Step 5: Test

```bash
# Generate a key (will trigger Touch ID prompt)
./target/release/minisign_rs -G --hardware-key -s test.key -p test.pub

# Sign a message (will trigger Touch ID prompt)
echo "test" > message.txt
./target/release/minisign_rs -S -s test.key -m message.txt

# Verify
./target/release/minisign_rs -V -p test.pub -m message.txt
```

## Why Is Signing Required?

macOS security policy requires:
- **Code signing** with proper entitlements to access Secure Enclave keys
- **DataProtectionKeychain** for storing SE keys (requires keychain-access-groups entitlement)

Without proper signing, you'll get error `-34018` (errSecMissingEntitlement).

## Troubleshooting

### "No valid identities found"

You need to create an Apple Development certificate in Xcode (see Step 1).

### "Certificate expired"

Generate a new certificate in Xcode (Accounts → Manage Certificates).

### "Touch ID not working"

1. Check System Settings → Touch ID & Password
2. Ensure Touch ID is enrolled
3. Ensure your Mac has Secure Enclave (Apple Silicon or T2 chip)

### "Still getting error -34018"

1. Verify signing: `codesign -dv ./target/release/minisign_rs`
2. Check entitlements: `codesign -d --entitlements - ./target/release/minisign_rs`
3. Rebuild after signing: `cargo build --release --features hw-keystore-macos`

## Architecture Requirements

Secure Enclave is available on:
- **Apple Silicon Macs** (M1, M2, M3, M4, etc.)
- **Intel Macs with T2 chip** (2018-2020 models)

Check your Mac model:
```bash
system_profiler SPHardwareDataType | grep "Chip"
```

## For CI/CD or Production

For production builds, you'll need:
1. A paid Apple Developer account
2. Distribution certificate
3. Proper provisioning profiles
4. Notarization (for distribution outside App Store)

## Related Files

- `entitlements.plist` - Required entitlements for Secure Enclave access
- `scripts/sign_for_secure_enclave.sh` - Helper script for code signing
- `src/hw_keystore/macos.rs` - Secure Enclave implementation
- `src/hw_keystore/mock.rs` - Mock implementation (no signing required)
