# Phase 5: Privacy Layer - Task Checklist

## Setup
- [x] Add `sphinx-packet` dependency to Cargo.toml
- [x] Create `privacy/` module structure

## Onion Routing

### Sphinx Packet Wrapper
- [x] Create `privacy/sphinx_wrapper.rs`
- [x] Implement `create_onion_packet()` - wrap payload in layered encryption
- [x] Implement `process_onion_packet()` - decrypt one layer at relay
- [ ] Implement SURB generation for replies (future)
- [x] Unit tests for wrap/unwrap roundtrip (3 tests passing)

### Circuit Building
- [x] Create `privacy/circuit.rs`
- [x] Implement relay registry for node discovery
- [x] Implement 3-hop path selection (avoid destination)
- [ ] Implement circuit caching/reuse
- [ ] Handle circuit failures with retry
- [x] Unit tests for circuit building (4 tests passing)

## Traffic Obfuscation

### Message Padding
- [x] Create `privacy/obfuscation.rs`
- [x] Implement fixed-size padding (4KB packets)
- [x] Implement unpadding on receive

### Timing Jitter
- [x] Implement random jitter delays (50-500ms)
- [x] Configurable cover traffic parameters

### Decoy Traffic
- [x] Implement decoy packet generation
- [x] Cover traffic configuration struct
- [x] Unit tests for obfuscation (7 tests passing)

## Relay Handler
- [x] Create `privacy/relay.rs`
- [x] Implement RelayHandler for nodes to forward packets
- [x] Implement relay statistics tracking
- [x] Unit tests for relay handling (3 tests passing)

## Integration (TODO)

### Network Layer
- [x] Add relay forwarding to behaviour.rs (Handled via PrivacyManager)
- [x] Add relay mode (opt-in) to node.rs (Handled via PrivacyManager)
- [x] Handle Sphinx packet routing
- [x] Implement robust auto-discovery (PeerConnected event)

### Messaging Layer
- [x] Add `use_onion_routing` flag to MessagingManager
- [x] Route messages through circuits when enabled
- [x] Unwrap incoming onion packets
- [x] Handle RelayAnnouncement messages

### CLI (p2p-test)
- [x] Add `--relay` flag to run as relay node (via /relay command)
- [x] Add `--onion` flag to enable onion routing (via /onion command)
- [x] Display circuit info when sending
- [x] Implement automatic relay discovery

## Testing
- [x] Debug and Fix Onion Routing
    - [x] Fix Protocol Header mismatch (Envelope wrapping)
    - [x] Fix Payload Size mismatch (8KB Padding)
    - [x] Fix Invalid Peer ID (32-byte Adress Extraction)
    - [x] Fix Payload Decryption (Truncate Padding at decrypt)
    - [x] Fix onion session identification by using `sender_peer_id`
    - [x] Fix EXIT RELAY bug (Forwarding unwrapped payload to destination)
- [x] Ensure automated responses are onion-wrapped
- [x] Fix CircuitBuilder to exclude destination from relay set
- [x] Verify identity attribution using diagnostic logs
- [x] Unit tests: Sphinx crypto (3 passing)
- [x] Unit tests: Circuit building (4 passing)
- [x] Unit tests: Obfuscation (7 passing)
- [x] Unit tests: Relay handler (3 passing)
- [x] Integration and Final Tests: 3-node relay chain (Fixed: hops, payload size, padding, protocol, exit-relay logic)
- [x] Manual test: iOS to CLI via relays (Verified working)

## iOS Integration
- [x] Add privacy toggle to settings (Implemented in `SettingsView`)
- [x] Wire `PrivacyAPI` into `AppViewModel` (Implemented)
- [x] Handle onion packet routing in Swift event loop (Implemented)
- [x] Support relay discovery via Signal events (Implemented via Auto-Announce)
- [x] Verify circuit building on simulator (Verified)
- [x] Add Manual Connect UI for troubleshooting (Implemented)
- [x] Push changes to repository (Pushed to main)

## Phase 6: Internet & Firewall Traversal (Stealth)
- [/] Research connectivity models (Invitation vs DHT vs Tor)
- [x] Implement QUIC transport for 5G stability
- [x] Implement Auto-Hole Punching (DCUTR)
- [x] **UniFFI Exposure**: Ensure `with_persistence` and `with_identity` are callable from Swift.
    - [x] Regenerate bindings for `create_configured_network_manager`.
    - [x] Add `generate_identity_bytes` to bindings.
- [x] **Verify Build**: Run `xcodebuild` successfully.
- [x] **Install & Run**: Install .app on Simulator.
- [x] **iOS Persistence**: Update `SecureChatApp` to manage `identity.key` and `peers.json` paths.
- [x] **QR Code Feature**:
    - [x] Create `InvitationView` (SwiftUI) to display QR code.
    - [x] Create `ScannerView` to scan friend's QR.
    - [x] Add Camera permission to `Info.plist` (via project settings).
    - [x] Parse QR data and call `dial_peer` in Rust.
- [x] Verify 5G-to-CLI connection (Manual verification successful)
