# P2P Mobile Chat

A secure, zero-trust, peer-to-peer messaging application for mobile devices.

## Project Goal

Build a truly private messenger where:
- Messages travel directly between devices with no central servers
- All communication is end-to-end encrypted using the Signal Protocol
- Metadata is protected through onion routing
- Users maintain full control over their cryptographic identity

## Features

**Core Messaging**
- Direct P2P messaging via Kademlia DHT
- Offline message storage through distributed network
- Contact management with QR code key exchange

**Security**
- Ed25519 identity keys for authentication
- X3DH key exchange for forward secrecy
- Double Ratchet for message encryption
- Zero-knowledge architecture

**Privacy**
- No phone numbers or email required
- Onion routing hides metadata
- Traffic obfuscation prevents analysis
- Self-destructing messages

**Performance**
- Native Rust core for speed and safety
- Native UI (SwiftUI/Compose) for best UX
- Local mDNS discovery for LAN messaging
- NAT traversal for direct connections

## Security

✅ **All messages are end-to-end encrypted using the Signal Protocol.**

- X3DH key exchange for session establishment
- Double Ratchet for forward secrecy
- Messages cannot be sent without an encrypted session

## Technology Stack

| Component | Technology |
|-----------|------------|
| Core | Rust |
| P2P | libp2p (Kademlia, mDNS, Noise) |
| Encryption | Signal Protocol |
| iOS UI | SwiftUI |
| iOS Bindings | UniFFI |
| Android UI | Jetpack Compose |

## Progress

| Phase | Status | Description |
|-------|--------|-------------|
| 1. Foundation | Complete | Rust core, UniFFI, iOS app |
| 2. P2P Networking | Complete | libp2p, mDNS, Kademlia DHT |
| 3. Encryption | Complete | Signal Protocol (X3DH, Double Ratchet) |
| 4. Messaging | Complete | Bidirectional (iOS/CLI), offline storage, fallback |
| 5. Privacy | Pending | Onion routing |
| 6. Polish | Pending | UI, Android, testing |

## Tests

```bash
cd core && cargo test
# 38 tests passing
```

## Quick Start

```bash
# Build and test Rust core
cd core && cargo test

# Run P2P test node
cargo run --bin p2p-test

# Build iOS app
cd ../SecureChatApp
xcodebuild -scheme SecureChatApp -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
```

## Project Structure

```
securechat/
├── core/                 # Rust library
│   ├── src/
│   │   ├── lib.rs       # Crypto functions
│   │   ├── network/     # P2P networking
│   │   └── bin/         # CLI tools
│   └── Cargo.toml
├── SecureChatApp/        # iOS app (SwiftUI)
├── ios-bindings/         # Generated Swift bindings
└── docs/                 # Documentation
```

## License

MIT
