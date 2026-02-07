# P2P Mobile Chat

A secure, zero-trust, peer-to-peer messaging app for mobile devices.

## 🎯 Project Goal

Build a private messenger with:
- **No servers** - Pure P2P via Kademlia DHT
- **End-to-end encryption** - Signal Protocol
- **Metadata privacy** - Onion routing
- **Native performance** - Rust core + native UI

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│           RUST CORE (Shared)            │
│  • libp2p (DHT, peer discovery)         │
│  • Signal Protocol (E2E encryption)     │
│  • Onion routing (metadata privacy)     │
└──────────────────┬──────────────────────┘
                   │ UniFFI bindings
         ┌─────────┴─────────┐
         ▼                   ▼
   ┌───────────┐       ┌───────────┐
   │    iOS    │       │  Android  │
   │  SwiftUI  │       │  Compose  │
   └───────────┘       └───────────┘
```

## 📊 Progress

| Phase | Status | Description |
|-------|--------|-------------|
| 1. Foundation | ✅ Complete | Rust core, UniFFI, iOS app |
| 2. P2P Networking | ✅ Complete | libp2p, mDNS, Kademlia DHT |
| 3. Encryption | ⏳ Pending | Signal Protocol |
| 4. Messaging | ⏳ Pending | Send/receive, offline storage |
| 5. Privacy | ⏳ Pending | Onion routing |
| 6. Polish | ⏳ Pending | UI, Android, testing |

## 🧪 Tests

```bash
cd core && cargo test
# 14 tests passing
```

## 🚀 Quick Start

```bash
# Build Rust core
cd core && cargo build --release

# Generate Swift bindings
cargo run --bin uniffi-bindgen generate src/securechat_core.udl --language swift --out-dir ../ios-bindings

# Build iOS app
cd ../SecureChatApp
xcodebuild -scheme SecureChatApp -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
```

## 📁 Structure

```
├── core/                 # Rust library
│   ├── src/
│   │   ├── lib.rs       # Crypto functions
│   │   └── network/     # P2P networking (libp2p)
│   │       ├── api.rs   # UniFFI wrapper
│   │       ├── node.rs  # P2P node
│   │       └── behaviour.rs
│   └── Cargo.toml
├── SecureChatApp/        # iOS app (SwiftUI)
├── ios-bindings/         # Generated Swift bindings
└── docs/                 # Documentation
```

## 📜 License

MIT
