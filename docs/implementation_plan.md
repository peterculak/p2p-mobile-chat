# Zero-Trust P2P Messenger - Native Mobile Implementation Plan

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    RUST CORE (Shared)                           │
│  • libp2p (DHT, peer discovery)                                 │
│  • Signal Protocol (E2E encryption)                             │
│  • Onion routing (metadata privacy)                             │
│  • SQLCipher (encrypted storage)                                │
└────────────────────────┬────────────────────────────────────────┘
                         │ UniFFI bindings
          ┌──────────────┴──────────────┐
          ▼                             ▼
   ┌─────────────┐               ┌─────────────┐
   │    iOS      │               │   Android   │
   │  SwiftUI    │               │   Compose   │
   └─────────────┘               └─────────────┘
```

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Core** | Rust |
| **P2P** | libp2p (Kademlia DHT) |
| **Crypto** | libsodium / ring |
| **Storage** | SQLite + SQLCipher |
| **iOS UI** | SwiftUI |
| **iOS Bindings** | UniFFI |
| **Android UI** | Jetpack Compose |
| **Android Bindings** | UniFFI → JNI |

---

## Project Structure

```
secure-messenger/
├── core/                    # Rust shared library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── crypto/         # Signal Protocol
│       ├── network/        # libp2p, DHT, onion
│       ├── storage/        # Encrypted SQLite
│       └── api/            # UniFFI exports
│
├── ios/                     # iOS app (SwiftUI)
│   └── SecureMessenger/
│
├── android/                 # Android app (Compose)
│   └── app/
│
└── uniffi/                  # Generated bindings
```

---

## Development Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Set up Rust project with Cargo
- [ ] Configure UniFFI for iOS bindings
- [ ] Create basic iOS app structure
- [ ] Implement key generation (Ed25519)
- [ ] Basic encrypted local storage

### Phase 2: Networking (Week 3-4)
- [ ] Integrate libp2p
- [ ] Implement Kademlia DHT
- [ ] Local network peer discovery (mDNS)
- [ ] NAT traversal (STUN/hole-punching)

### Phase 3: Encryption (Week 5-6)
- [ ] Signal Protocol implementation
- [ ] X3DH key exchange
- [ ] Double Ratchet
- [ ] Session management

### Phase 4: Messaging (Week 7-8)
- [ ] Message send/receive
- [ ] Offline message storage (DHT)
- [ ] Contact management
- [ ] QR code key exchange

### Phase 5: Privacy (Week 9-10)
- [ ] Onion routing layer
- [ ] Traffic obfuscation
- [ ] Anonymous DHT lookups

### Phase 6: Polish (Week 11-12)
- [ ] UI/UX improvements
- [ ] Android port
- [ ] Testing & security audit

---

## Testing Strategy

| Level | Method |
|-------|--------|
| **Unit** | Rust tests for crypto/network |
| **Integration** | Docker multi-peer simulation |
| **Mobile** | iOS Simulator + real devices |
| **Network** | Cross-network NAT testing |

---

## Key Features

- ✅ **No servers** - Pure P2P via DHT
- ✅ **Metadata hidden** - Onion routing
- ✅ **Forward secrecy** - Signal Protocol
- ✅ **Works offline** - Store-and-forward DHT
- ✅ **Native performance** - Rust core
