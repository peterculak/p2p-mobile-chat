# SecureChat P2P Messenger - Development Tasks

## Phase 1: POC Foundation ✅
- [x] Set up Rust core project
- [x] Add cryptography (key generation)
- [x] Configure UniFFI for iOS bindings
- [x] Create basic iOS app
- [x] Connect iOS to Rust core

## Phase 2: P2P Networking ✅
- [x] Add libp2p dependencies to Cargo.toml
- [x] Create network module structure
- [x] Implement P2P node (start/stop)
- [x] Implement Kademlia DHT for peer discovery
- [x] Local peer discovery (mDNS)
- [x] NAT traversal (dcutr/relay)
- [x] Write Rust tests for network layer (14 tests passing)
- [x] Expose network API via UniFFI
- [x] Integrate network with iOS app

## Phase 3: Encryption
- [ ] Signal Protocol
- [ ] X3DH key exchange
- [ ] Double Ratchet
- [ ] Session management

## Phase 4: Messaging
- [ ] Send/receive messages
- [ ] Offline storage (DHT)
- [ ] Contact management
- [ ] QR code exchange

## Phase 5: Privacy
- [ ] Onion routing
- [ ] Traffic obfuscation

## Phase 6: Polish
- [ ] Premium UI
- [ ] Android port
- [ ] Testing
