---
description: How to build the SecureChat app with fresh Rust code
---

# Build SecureChat

The Xcode project does NOT automatically rebuild the Rust core. You MUST build Rust separately first.

## Full rebuild (simulator + device)

// turbo-all

1. Build Rust core for simulator:
```bash
cd /Users/peter2/src/securechat/core && cargo build --target aarch64-apple-ios-sim
```

2. Build Rust core for device:
```bash
cd /Users/peter2/src/securechat/core && cargo build --target aarch64-apple-ios
```

3. Build the iOS app for simulator:
```bash
cd /Users/peter2/src/securechat && xcodebuild -project SecureChatApp/SecureChatApp.xcodeproj -scheme SecureChatApp -configuration Debug -sdk iphonesimulator -arch arm64 build 2>&1 | tail -5
```

4. To install on physical device, open Xcode and press Cmd+R:
```bash
open /Users/peter2/src/securechat/SecureChatApp/SecureChatApp.xcodeproj
```

## Quick check: verify Rust lib is fresh
```bash
ls -la /Users/peter2/src/securechat/core/target/aarch64-apple-ios-sim/debug/libsecurechat_core.a | awk '{print $6, $7, $8}'
ls -la /Users/peter2/src/securechat/core/target/aarch64-apple-ios/debug/libsecurechat_core.a | awk '{print $6, $7, $8}'
```

## IMPORTANT
- After ANY change to Rust code in `core/src/`, you MUST run steps 1-2 before building in Xcode
- Xcode `BUILD SUCCEEDED` does NOT mean Rust was rebuilt — it only compiles Swift
