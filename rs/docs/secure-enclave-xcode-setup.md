# Secure Enclave Access via Xcode Wrapper (Free Apple ID)

This guide shows how to enable real Secure Enclave access using a **free Apple ID** by creating an Xcode wrapper project.

## Why This Works

According to research and testing:
- CLI binaries cannot store provisioning profiles
- `keychain-access-groups` entitlement requires a provisioning profile
- Xcode not only signs but **registers profiles with the system**
- This registration allows SE access on your specific Mac

## One-Time Setup (5 minutes)

### Step 1: Create Xcode Project

1. Open **Xcode**
2. **File → New → Project**
3. Select **macOS → Command Line Tool**
4. Configure:
   - **Product Name:** `minisign_wrapper`
   - **Organization Identifier:** `com.minisign`
   - **Language:** Swift
   - **Location:** `<repo>/xcode_wrapper/`
5. Click **Create**

### Step 2: Configure Signing

1. Select project in sidebar
2. Select target **minisign_wrapper**
3. Go to **Signing & Capabilities** tab
4. ✅ Check **Automatically manage signing**
5. **Team:** Select your Apple ID (free account)
6. Xcode will automatically create provisioning profile

### Step 3: Add Keychain Entitlement

1. Still in **Signing & Capabilities**
2. Click **+ Capability**
3. Add **Keychain Sharing**
4. In **Keychain Groups**, add: `com.minisign.rs`
5. Xcode updates entitlements automatically

### Step 4: Create Wrapper Code

Replace contents of `main.swift` with:

```swift
import Foundation

// Wrapper that executes the Cargo-built binary
// Inherits this wrapper's code signature and provisioning profile

let task = Process()
task.executableURL = URL(fileURLWithPath: "../target/release/minisign_rs")
task.arguments = CommandLine.arguments.dropFirst().map(String.init)

do {
    try task.run()
    task.waitUntilExit()
    exit(task.terminationStatus)
} catch {
    print("Failed to execute minisign_rs: \(error)")
    exit(1)
}
```

### Step 5: Build

1. **Product → Build** (⌘B)
2. Xcode builds, signs, and **registers the provisioning profile**
3. Binary location: `~/Library/Developer/Xcode/DerivedData/.../Release/minisign_wrapper`

## Automated Build (After Setup)

Once the Xcode project exists, use the automated script:

```bash
./scripts/build_with_se_access.sh
```

This will:
1. Build Rust binary with `cargo`
2. Build Xcode wrapper with `xcodebuild`
3. Create symlink: `./minisign_rs_se`

## Usage

```bash
# Generate key with Secure Enclave (triggers Touch ID)
./minisign_rs_se -G --hardware-key -s test.key -p test.pub

# Sign message (triggers Touch ID)
echo "test" > message.txt
./minisign_rs_se -S -s test.key -m message.txt

# Verify (no Touch ID needed)
./minisign_rs_se -V -p test.pub -m message.txt
```

## How It Works

```
┌─────────────────────────────────────────┐
│  minisign_wrapper (Xcode-built)         │
│  ├─ Code signature                      │
│  ├─ Provisioning profile (embedded)     │
│  └─ Registered with system keychain     │
└──────────────┬──────────────────────────┘
               │ executes ↓
┌──────────────▼──────────────────────────┐
│  minisign_rs (Cargo-built)              │
│  ├─ Inherits wrapper's credentials      │
│  └─ Can access Secure Enclave!          │
└─────────────────────────────────────────┘
```

The wrapper acts as a trusted intermediary that:
1. Has proper provisioning profile (Xcode-generated)
2. Is registered with the system (via Xcode build)
3. Executes your Cargo binary with inherited privileges

## Troubleshooting

### "Developer cannot be verified"

1. **System Settings → Privacy & Security**
2. Allow apps from your developer team

### "No provisioning profiles found"

1. Xcode → Settings → Accounts
2. Select your Apple ID → **Manage Certificates**
3. Ensure "Apple Development" certificate exists
4. In project, click **Download Manual Profiles**

### "SIGKILL when running wrapper"

1. Check entitlements: `codesign -d --entitlements :- DerivedData/.../minisign_wrapper`
2. Verify provisioning profile exists (Xcode should show it)
3. Rebuild the Xcode project (⌘B)

### "Still getting error -34018"

The provisioning profile might not be registered. Try:
1. Clean build folder: **Product → Clean Build Folder** (⌘⇧K)
2. Rebuild: **Product → Build** (⌘B)
3. If still fails, delete DerivedData and rebuild

## Limitations

- **Mac-specific:** Wrapper only works on the Mac where Xcode built it
- **Requires Xcode:** Can't distribute to users without Xcode setup
- **Free account limits:** 7-day provisioning profile expiration (rebuild required)

## For Distribution

If you want to distribute the SE-enabled binary:
- **Paid Developer Program required** ($99/year)
- Notarization needed for public distribution
- Provisioning profiles last 1 year (vs 7 days for free)

## References

- [Apple Forums: CLI tools and Secure Enclave](https://developer.apple.com/forums/thread/125510)
- [Xcode Automatic Signing](https://developer.apple.com/documentation/xcode/preparing-your-app-for-distribution)
