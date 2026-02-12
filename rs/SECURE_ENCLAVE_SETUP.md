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

### Option 2: Real Secure Enclave (Requires App Bundle + Xcode)

To use the actual Secure Enclave on your Mac, you need to wrap the CLI tool in an app bundle because **CLI tools cannot store provisioning profiles**.

#### Important Note

According to [Apple Developer Forums](https://developer.apple.com/forums/thread/125510):
> "To interact with keys protected by the Secure Enclave you must use the iOS-style keychain, which requires an entitlement authorized by a provisioning profile. A tool has nowhere to store a provisioning profile and thus Xcode doesn't do the right thing out of the box. The solution is to embed your tool in an app-like structure."

#### Step 1: Get Apple Developer Certificate

1. Open **Xcode**
2. Go to **Xcode → Settings → Accounts**
3. Click **+** to add your Apple ID (free account works)
4. Select your account → **Manage Certificates**
5. Click **+** → **Apple Development**

#### Step 2: Create Xcode Wrapper Project

You'll need to create an Xcode project that:
1. Wraps the Cargo-built binary in an app bundle
2. Configures proper entitlements
3. Lets Xcode handle code signing (which embeds the provisioning profile)

**The app bundle structure:**
```
minisign_rs.app/
└── Contents/
    ├── Info.plist
    ├── MacOS/
    │   └── minisign_rs (your Cargo-built binary)
    └── embedded.provisionprofile (added automatically by Xcode)
```

#### Step 3: Build with Cargo, Package with Xcode

```bash
# 1. Build the binary with Cargo
cargo build --release --features hw-keystore-macos

# 2. Use Xcode to wrap, sign, and embed provisioning profile
# (Xcode project setup required - see docs/secure-enclave-limitations.md)
```

#### Step 4: Run from App Bundle

```bash
# Run the tool from within the app bundle
minisign_rs.app/Contents/MacOS/minisign_rs -G --hardware-key -s test.key -p test.pub

# Or create a symlink for convenience
ln -s "$(pwd)/minisign_rs.app/Contents/MacOS/minisign_rs" /usr/local/bin/minisign_rs
```

**Note:** Manual signing with `codesign` does NOT work because it doesn't embed provisioning profiles. Xcode must handle the signing.

## Why Is an App Bundle Required?

macOS Secure Enclave access requires:
1. **Provisioning profile** to authorize entitlements
2. **Provisioning profiles** can only be stored in app bundles (`Contents/embedded.provisionprofile`)
3. **CLI binaries** have nowhere to store provisioning profiles
4. **Solution:** Wrap CLI tool in app bundle structure

Without an app bundle:
- Error `-34018` (errSecMissingEntitlement) when trying to access SE
- OR process killed (exit 137 / SIGKILL) if entitlements are present but no provisioning profile

## Troubleshooting

### "No valid identities found"

You need to create an Apple Development certificate in Xcode (see Step 1).

### "Certificate expired"

Generate a new certificate in Xcode (Accounts → Manage Certificates).

### "Touch ID not working"

1. Check System Settings → Touch ID & Password
2. Ensure Touch ID is enrolled
3. Ensure your Mac has Secure Enclave (Apple Silicon or T2 chip)

### "Still getting error -34018 or exit 137"

**Error -34018 (errSecMissingEntitlement):**
- The binary lacks proper entitlements or provisioning profile
- Check: `ls minisign_rs.app/Contents/embedded.provisionprofile` (must exist)

**Exit 137 (SIGKILL):**
- Entitlements present but no provisioning profile embedded
- Using `codesign` directly doesn't embed provisioning profiles
- **Solution:** Use Xcode to build/sign the app bundle

**Verify app bundle signing:**
```bash
codesign -dv minisign_rs.app
codesign -d --entitlements :- minisign_rs.app
ls -la minisign_rs.app/Contents/embedded.provisionprofile
```

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
1. App bundle structure (required for all SE access)
2. Apple Developer account (free works, paid recommended)
3. Distribution certificate (paid account)
4. Proper provisioning profiles (automated by Xcode)
5. Notarization (for distribution outside App Store - paid account required)

**Recommendation:** Use Mock KeyStore in CI (no hardware needed, all tests pass). Only test real SE manually on physical hardware.

## Related Files

- `entitlements.plist` - Required entitlements for Secure Enclave access
- `scripts/sign_for_secure_enclave.sh` - Helper script for code signing
- `src/hw_keystore/macos.rs` - Secure Enclave implementation
- `src/hw_keystore/mock.rs` - Mock implementation (no signing required)
