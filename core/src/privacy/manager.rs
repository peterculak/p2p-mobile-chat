//! Privacy Manager - High-level interface for onion routing integration
//!
//! Orchestrates circuit building, relay handling, and message routing.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use crate::privacy::{
    circuit::{RelayRegistry, CircuitBuilder, Circuit}, // Added Circuit
    sphinx_wrapper::{self, OnionDestination, create_onion_packet}, // Removed OnionOutgoing (defined here)
    relay::{RelayHandler, RelayEvent},
    obfuscation::{self, random_jitter_ms},
};
// Removed config::PrivacyConfig import as it is defined in this file
use tracing::{info, debug, warn};

/// Configuration for the privacy layer
#[derive(Debug, Clone)]
pub struct PrivacyConfig {
    /// Enable onion routing for outgoing messages
    pub onion_routing_enabled: bool,
    /// Act as a relay for other nodes
    pub relay_enabled: bool,
    /// Minimum number of hops (default: 3)
    pub min_hops: usize,
    /// Apply timing jitter to messages
    pub jitter_enabled: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            onion_routing_enabled: false,
            relay_enabled: true, // All nodes relay by default
            min_hops: 2, // 2 hops sufficient for POC (Sender -> R1 -> R2 -> Receiver)
            jitter_enabled: true,
        }
    }
}

/// Events from the privacy manager
#[derive(Debug, Clone)]
pub enum PrivacyEvent {
    /// Relay packet to next hop
    RelayPacket {
        next_peer_id: String,
        packet_bytes: Vec<u8>,
        delay_ms: u64,
    },
    /// Packet arrived at destination - deliver to messaging layer
    PacketDelivered {
        payload: Vec<u8>,
    },
    /// Forward unwrapped payload to final destination (exit node role)
    DeliverPayload {
        next_peer_id: String,
        payload: Vec<u8>,
    },
    /// Error occurred
    Error {
        message: String,
    },
    /// Circuit built successfully
    CircuitBuilt {
        circuit_id: u64,
        hops: usize,
    },
}

/// Outgoing onion packet ready to send
#[derive(Debug, Clone)]
pub struct OnionOutgoing {
    /// First hop peer ID
    pub entry_peer_id: String,
    /// Encrypted packet
    pub packet_bytes: Vec<u8>,
    /// Delay before sending (ms)
    pub delay_ms: u64,
}

/// Manages privacy features including onion routing and relaying
pub struct PrivacyManager {
    /// Configuration
    config: PrivacyConfig,
    /// Relay handler for processing packets
    relay_handler: RelayHandler,
    /// Registry of known relays
    relay_registry: Arc<RwLock<RelayRegistry>>,
    /// Circuit builder  
    circuit_builder: CircuitBuilder,
    /// Active circuits (destination peer_id -> circuit)
    active_circuits: HashMap<String, Circuit>,
    /// Event queue
    events: Vec<PrivacyEvent>,
    /// Pending outgoing packets
    outgoing: Vec<OnionOutgoing>,
}

// Helper functions now in sphinx_wrapper

impl PrivacyManager {
    /// Create a new privacy manager
    pub fn new(config: PrivacyConfig) -> Self {
        let relay_registry = Arc::new(RwLock::new(RelayRegistry::new()));
        let circuit_builder = CircuitBuilder::new(relay_registry.clone());
        let mut relay_handler = RelayHandler::new();
        relay_handler.set_relay_enabled(config.relay_enabled);
        
        Self {
            config,
            relay_handler,
            relay_registry,
            circuit_builder,
            active_circuits: HashMap::new(),
            events: Vec::new(),
            outgoing: Vec::new(),
        }
    }
    
    /// Get our relay public key (for advertising to other nodes)
    pub fn relay_public_key(&self) -> [u8; 32] {
        *self.relay_handler.public_key()
    }
    
    /// Register a peer as a relay node
    pub fn register_relay(&mut self, peer_id: &str, public_key: [u8; 32]) {
        self.relay_registry.write().unwrap().register(peer_id.to_string(), public_key);
        debug!("Registered relay: {} (total: {})", 
            peer_id, self.relay_registry.read().unwrap().count());
    }
    
    /// Unregister a relay (e.g., on disconnect)
    pub fn unregister_relay(&mut self, peer_id: &str) {
        self.relay_registry.write().unwrap().unregister(peer_id);
        // Remove any circuits using this relay
        self.active_circuits.retain(|_, circuit| {
            !circuit.hops.iter().any(|h| String::from_utf8_lossy(&h.address) == peer_id)
        });
    }
    
    /// Check if onion routing is enabled
    pub fn is_onion_enabled(&self) -> bool {
        self.config.onion_routing_enabled
    }
    
    /// Enable or disable onion routing
    pub fn set_onion_enabled(&mut self, enabled: bool) {
        self.config.onion_routing_enabled = enabled;
        info!("Onion routing: {}", if enabled { "enabled" } else { "disabled" });
    }
    
    /// Check if we have enough relays for a circuit
    pub fn can_build_circuit(&self) -> bool {
        self.relay_registry.read().unwrap().count() >= self.config.min_hops
    }
    
    /// Get number of known relays
    pub fn relay_count(&self) -> usize {
        self.relay_registry.read().unwrap().count()
    }
    
    /// Wrap a message for sending through onion routing
    ///
    /// Returns None if onion routing is disabled or not enough relays
    pub fn wrap_message(&mut self, payload: &[u8], destination_peer_id: &str) -> Option<OnionOutgoing> {
        if !self.config.onion_routing_enabled {
            return None;
        }
        
        // Get or build circuit for this destination
        let circuit = self.get_or_build_circuit(destination_peer_id)?;
        
        // Create onion destination using helper to get 32-byte key
        let dest_bytes = sphinx_wrapper::peer_id_to_bytes(destination_peer_id)?;
        let destination = OnionDestination::new(dest_bytes);
        
        // Create onion packet - sphinx handles its own padding internally
         match create_onion_packet(payload, &circuit.hops, &destination) {
            Ok(raw_packet_bytes) => {
                // Convert stored entry node bytes back to Peer ID string for logging
                let entry_peer_id_bytes = circuit.entry_node()?;
                let entry_peer_id = sphinx_wrapper::bytes_to_peer_id(entry_peer_id_bytes);
                
                let delay_ms = if self.config.jitter_enabled { random_jitter_ms() } else { 0 };
                
                debug!("Created onion packet for {} via {} ({} hops)", 
                    destination_peer_id, entry_peer_id, circuit.hops.len());
                
                // PAD to FIXED_PACKET_SIZE
                // Use generate_decoy to get random bytes, then overwrite with packet
                let mut packet_bytes = obfuscation::generate_decoy();
                if raw_packet_bytes.len() > packet_bytes.len() {
                    warn!("Packet too large: {} > {}", raw_packet_bytes.len(), packet_bytes.len());
                    return None;
                }
                packet_bytes[..raw_packet_bytes.len()].copy_from_slice(&raw_packet_bytes);

                Some(OnionOutgoing {
                    entry_peer_id,
                    packet_bytes,
                    delay_ms,
                })
            }
            Err(e) => {
                warn!("Failed to create onion packet: {}", e);
                self.events.push(PrivacyEvent::Error {
                    message: format!("Onion packet creation failed: {}", e),
                });
                None
            }
        }
    }
    
    /// Process an incoming packet
    /// Returns true if the packet was an onion packet and was processed
    pub fn process_incoming(&mut self, packet_bytes: &[u8]) -> bool {
        // First check if it's the correct fixed size
        // If not, it's definitely not an onion packet
        if packet_bytes.len() != obfuscation::FIXED_PACKET_SIZE {
            info!("PrivacyManager: Rejecting packet due to size mismatch: {} != {}", 
                packet_bytes.len(), obfuscation::FIXED_PACKET_SIZE);
            return false;
        }

        info!("PrivacyManager: Handing packet to relay_handler...");
        let success = self.relay_handler.handle_packet(packet_bytes);
        
        // Process relay handler events
        while let Some(event) = self.relay_handler.next_event() {
            match event {
                RelayEvent::Forward(fwd) => {
                    let next_peer_id = sphinx_wrapper::bytes_to_peer_id(&fwd.next_address);
                    let delay_ms = if self.config.jitter_enabled {
                        fwd.delay_ms + random_jitter_ms()
                    } else {
                        fwd.delay_ms
                    };
                    
                    info!("PrivacyManager: Forwarding packet to {} (delay: {}ms)", next_peer_id, delay_ms);
                    
                    let mut packet_bytes = fwd.packet_bytes;
                    if packet_bytes.len() < obfuscation::FIXED_PACKET_SIZE {
                        let mut padded = obfuscation::generate_decoy();
                        padded[..packet_bytes.len()].copy_from_slice(&packet_bytes);
                        packet_bytes = padded;
                    }

                    self.events.push(PrivacyEvent::RelayPacket {
                        next_peer_id,
                        packet_bytes,
                        delay_ms,
                    });
                }
                RelayEvent::ForwardPayload(fwd) => {
                    let next_peer_id = sphinx_wrapper::bytes_to_peer_id(&fwd.next_address);
                    info!("PrivacyManager: Exit node role - delivering payload to {}", next_peer_id);
                    self.events.push(PrivacyEvent::DeliverPayload {
                        next_peer_id,
                        payload: fwd.packet_bytes,
                    });
                }
                RelayEvent::Delivered(delivered) => {
                    info!("PrivacyManager: REACHED FINAL DESTINATION! Payload size: {} bytes", delivered.payload.len());
                    self.events.push(PrivacyEvent::PacketDelivered {
                        payload: delivered.payload,
                    });
                }
                RelayEvent::Error(e) => {
                    info!("PrivacyManager: Relay error: {}", e);
                    self.events.push(PrivacyEvent::Error { message: e });
                }
            }
        }
        
        info!("PrivacyManager: process_incoming result: success={}", success);
        success
    }
    
    /// Get next event
    pub fn next_event(&mut self) -> Option<PrivacyEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }
    
    /// Get next outgoing packet
    pub fn next_outgoing(&mut self) -> Option<OnionOutgoing> {
        if self.outgoing.is_empty() {
            None
        } else {
            Some(self.outgoing.remove(0))
        }
    }
    
    /// Get relay statistics
    pub fn relay_stats(&self) -> (u64, u64, bool) {
        let stats = self.relay_handler.stats();
        (stats.packets_relayed, stats.packets_delivered, stats.is_enabled)
    }
    
    /// Get or build a circuit for a destination
    fn get_or_build_circuit(&mut self, destination_peer_id: &str) -> Option<Circuit> {
        // Check if we have a cached circuit
        if let Some(circuit) = self.active_circuits.get(destination_peer_id) {
            return Some(circuit.clone());
        }
        
        // Build new circuit
        match self.circuit_builder.build_circuit(Some(destination_peer_id)) {
            Ok(circuit) => {
                info!("Built circuit {} with {} hops for {}", 
                    circuit.id, circuit.hops.len(), destination_peer_id);
                
                self.events.push(PrivacyEvent::CircuitBuilt {
                    circuit_id: circuit.id,
                    hops: circuit.hops.len(),
                });
                
                self.active_circuits.insert(destination_peer_id.to_string(), circuit.clone());
                Some(circuit)
            }
            Err(e) => {
                warn!("Failed to build circuit: {}", e);
                self.events.push(PrivacyEvent::Error {
                    message: format!("Circuit build failed: {}", e),
                });
                None
            }
        }
    }
    
    /// Clear cached circuit for a destination (e.g., after failure)
    pub fn invalidate_circuit(&mut self, destination_peer_id: &str) {
        self.active_circuits.remove(destination_peer_id);
    }
    
    /// Clear all circuits
    pub fn clear_circuits(&mut self) {
        self.active_circuits.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::generate_relay_keypair;

    #[test]
    fn test_privacy_manager_creation() {
        let config = PrivacyConfig::default();
        let manager = PrivacyManager::new(config);
        
        assert!(!manager.is_onion_enabled());
        assert_eq!(manager.relay_count(), 0);
    }

    #[test]
    fn test_register_relays() {
        let config = PrivacyConfig::default();
        let mut manager = PrivacyManager::new(config);
        
        for i in 0..5 {
            let (_, public_key) = generate_relay_keypair();
            manager.register_relay(&format!("peer{}", i), public_key);
        }
        
        assert_eq!(manager.relay_count(), 5);
        assert!(manager.can_build_circuit());
    }

    #[test]
    fn test_wrap_message_disabled() {
        let config = PrivacyConfig::default();
        let mut manager = PrivacyManager::new(config);
        
        let result = manager.wrap_message(b"test message", "destination");
        assert!(result.is_none()); // Onion routing disabled
    }

    #[test]
    fn test_wrap_message_not_enough_relays() {
        let mut config = PrivacyConfig::default();
        config.onion_routing_enabled = true;
        let mut manager = PrivacyManager::new(config);
        
        // Add only 2 relays (need 3)
        for i in 0..2 {
            let (_, public_key) = generate_relay_keypair();
            manager.register_relay(&format!("peer{}", i), public_key);
        }
        
        let result = manager.wrap_message(b"test message", "destination");
        assert!(result.is_none()); // Not enough relays
    }

    #[test]
    fn test_full_onion_flow() {
        // Create 3 relay nodes
        let (_, public1) = generate_relay_keypair();
        let (_, public2) = generate_relay_keypair();
        let (_, public3) = generate_relay_keypair();
        
        // Sender's privacy manager
        let mut sender_config = PrivacyConfig::default();
        sender_config.onion_routing_enabled = true;
        let mut sender = PrivacyManager::new(sender_config);
        
        sender.register_relay("relay1", public1);
        sender.register_relay("relay2", public2);
        sender.register_relay("relay3", public3);
        
        assert_eq!(sender.relay_count(), 3);
        assert!(sender.can_build_circuit());
        
        // Create onion packet
        let payload = b"Secret message through onion routing!";
        let onion_result = sender.wrap_message(payload, "destination");
        
        // Check for any error events
        while let Some(event) = sender.next_event() {
            match event {
                PrivacyEvent::Error { message } => {
                    panic!("Error event: {}", message);
                }
                PrivacyEvent::CircuitBuilt { circuit_id, hops } => {
                    println!("Circuit {} built with {} hops", circuit_id, hops);
                }
                _ => {}
            }
        }
        
        // This should succeed now we have 3 relays
        assert!(onion_result.is_some(), "wrap_message should succeed with 3 relays");
        
        let onion = onion_result.unwrap();
        assert!(!onion.entry_peer_id.is_empty());
        assert!(!onion.packet_bytes.is_empty());
    }
}
