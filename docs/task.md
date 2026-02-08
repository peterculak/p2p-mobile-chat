# SecureChat P2P Messenger - Development Tasks

## Phase 1: POC Foundation [Complete]
- [x] Set up Rust core project
- [x] Add cryptography (key generation)
- [x] Configure UniFFI for iOS bindings
- [x] Create basic iOS app
- [x] Connect iOS to Rust core

## Phase 2: P2P Networking [Complete]
- [x] Add libp2p dependencies to Cargo.toml
- [x] Create network module structure
- [x] Implement P2P node (start/stop)
- [x] Implement Kademlia DHT for peer discovery
- [x] Local peer discovery (mDNS)
- [x] NAT traversal (dcutr/relay)
- [x] Write Rust tests for network layer
- [x] Expose network API via UniFFI
- [x] Integrate network with iOS app

## Phase 3: Encryption [Complete]
- [x] Add crypto dependencies (aes-gcm, hkdf, hmac, zeroize)
- [x] Implement X3DH key exchange
- [x] Implement Double Ratchet with forward secrecy
- [x] Session management API
- [x] Comprehensive tests (38 total)

## Phase 4: Messaging
- [x] Send/receive messages over P2P (bidirectional CLI ↔ Phone)
- [ ] Offline storage (DHT) [deferred]
- [ ] Contact management [deferred]
- [ ] QR code exchange [deferred]

## Phase 5: Privacy [Current]
- [ ] Onion routing layer
  - [ ] Circuit building (3-hop paths)
  - [ ] Layered encryption (wrap/unwrap)
  - [ ] Relay node discovery via DHT
- [ ] Traffic obfuscation
  - [ ] Message padding
  - [ ] Timing jitter
  - [ ] Decoy traffic

## Phase 6: Polish
- [ ] Premium UI
- [ ] Android port
- [ ] Testing
