//! Relay node functionality for forwarding onion packets
//!
//! Allows nodes to participate as relays in the onion routing network.

use crate::privacy::sphinx_wrapper::{process_onion_packet, ProcessResult, generate_relay_keypair};
use std::collections::VecDeque;
use tracing::{info, debug, warn};

/// A packet that needs to be forwarded
#[derive(Debug, Clone)]
pub struct ForwardPacket {
    /// Next hop address
    pub next_address: Vec<u8>,
    /// The packet data 
    pub packet_bytes: Vec<u8>,
    /// Delay before sending (ms)
    pub delay_ms: u64,
}

/// A packet that has reached its destination
#[derive(Debug, Clone)]
pub struct DeliveredPacket {
    /// The decrypted payload
    pub payload: Vec<u8>,
    /// Message identifier
    pub identifier: [u8; 16],
}

/// Events from the relay handler
#[derive(Debug)]
pub enum RelayEvent {
    /// Forward this onion packet to the next hop
    Forward(ForwardPacket),
    /// Forward the unwrapped payload to the final destination (exit node role)
    ForwardPayload(ForwardPacket),
    /// This packet is for us (final destination reached)
    Delivered(DeliveredPacket),
    /// Error processing packet
    Error(String),
}

/// Handles relay operations for this node
pub struct RelayHandler {
    /// Our X25519 private key for decrypting onion layers
    private_key: [u8; 32],
    /// Our X25519 public key
    public_key: [u8; 32],
    /// Whether we're acting as a relay for others
    is_relay_enabled: bool,
    /// Queue of outgoing events
    events: VecDeque<RelayEvent>,
    /// Statistics
    packets_relayed: u64,
    packets_delivered: u64,
}

impl RelayHandler {
    /// Create a new relay handler with a fresh keypair
    pub fn new() -> Self {
        let (private_key, public_key) = generate_relay_keypair();
        Self {
            private_key,
            public_key,
            is_relay_enabled: true, // All nodes are relays by default
            events: VecDeque::new(),
            packets_relayed: 0,
            packets_delivered: 0,
        }
    }
    
    /// Create with an existing keypair
    pub fn with_keypair(private_key: [u8; 32], public_key: [u8; 32]) -> Self {
        Self {
            private_key,
            public_key,
            is_relay_enabled: true,
            events: VecDeque::new(),
            packets_relayed: 0,
            packets_delivered: 0,
        }
    }
    
    /// Get our public key (for advertising as a relay)
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    
    /// Enable or disable relay functionality
    pub fn set_relay_enabled(&mut self, enabled: bool) {
        self.is_relay_enabled = enabled;
        info!("Relay mode: {}", if enabled { "enabled" } else { "disabled" });
    }
    
    /// Check if relay mode is enabled
    pub fn is_relay_enabled(&self) -> bool {
        self.is_relay_enabled
    }
    
    /// Process an incoming onion packet
    ///
    /// Returns true if the packet was successfully processed
    pub fn handle_packet(&mut self, packet_bytes: &[u8]) -> bool {
        info!("RelayHandler: Processing packet with our public key: {}", hex::encode(&self.public_key));
        match process_onion_packet(packet_bytes, &self.private_key) {
            Ok(ProcessResult::Forward { next_address, packet_bytes, delay_ms }) => {
                if !self.is_relay_enabled {
                    info!("RelayHandler: Received relay packet but relay mode is disabled");
                    self.events.push_back(RelayEvent::Error(
                        "Relay mode disabled".to_string()
                    ));
                    return false;
                }
                
                info!("RelayHandler: Result = FORWARD to {}", hex::encode(&next_address));
                self.packets_relayed += 1;
                
                self.events.push_back(RelayEvent::Forward(ForwardPacket {
                    next_address,
                    packet_bytes,
                    delay_ms,
                }));
                true
            }
            Ok(ProcessResult::Destination { destination_address, payload, identifier }) => {
                if destination_address == self.public_key {
                    info!("RelayHandler: Result = DESTINATION reached! It is for US. Payload size: {}", payload.len());
                    self.packets_delivered += 1;
                    
                    self.events.push_back(RelayEvent::Delivered(DeliveredPacket {
                        payload,
                        identifier,
                    }));
                } else {
                    let next_peer_id = crate::privacy::sphinx_wrapper::bytes_to_peer_id(&destination_address);
                    info!("RelayHandler: Result = EXIT NODE role. Forwarding payload to {}", next_peer_id);
                    
                    self.packets_relayed += 1;
                    self.events.push_back(RelayEvent::ForwardPayload(ForwardPacket {
                        next_address: destination_address,
                        packet_bytes: payload,
                        delay_ms: 0, // Exit node forwards are immediate or use jitter from manager
                    }));
                }
                true
            }
            Err(e) => {
                info!("RelayHandler: Sphinx error: {}", e);
                self.events.push_back(RelayEvent::Error(e.to_string()));
                false
            }
        }
    }
    
    /// Get next pending event
    pub fn next_event(&mut self) -> Option<RelayEvent> {
        self.events.pop_front()
    }
    
    /// Get relay statistics
    pub fn stats(&self) -> RelayStats {
        RelayStats {
            packets_relayed: self.packets_relayed,
            packets_delivered: self.packets_delivered,
            is_enabled: self.is_relay_enabled,
        }
    }
}

impl Default for RelayHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about relay operations
#[derive(Debug, Clone)]
pub struct RelayStats {
    pub packets_relayed: u64,
    pub packets_delivered: u64,
    pub is_enabled: bool,
}

/// Relay node information for advertising
#[derive(Debug, Clone)]
pub struct RelayNodeInfo {
    /// Peer ID
    pub peer_id: String,
    /// X25519 public key for onion encryption
    pub public_key: [u8; 32],
    /// Whether the node is currently available
    pub available: bool,
}

impl RelayNodeInfo {
    pub fn new(peer_id: String, public_key: [u8; 32]) -> Self {
        Self {
            peer_id,
            public_key,
            available: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::sphinx_wrapper::{RelayNode, OnionDestination, create_onion_packet};

    #[test]
    fn test_relay_handler_creation() {
        let handler = RelayHandler::new();
        assert!(handler.is_relay_enabled());
        assert_eq!(handler.stats().packets_relayed, 0);
    }

    #[test]
    fn test_relay_forwarding() {
        // Create two relay handlers (simulating 2 nodes)
        let relay1 = RelayHandler::new();
        let mut relay2 = RelayHandler::new();
        
        // Create a packet through relay1 to destination relay2
        let route = vec![
            RelayNode::new(b"relay1".to_vec(), *relay1.public_key()),
        ];
        let destination = OnionDestination::new(b"relay2".to_vec());
        let payload = b"test message";
        
        let packet = create_onion_packet(payload, &route, &destination).unwrap();
        
        // Relay1 should forward it (but since it's single hop, it becomes destination)
        let mut handler1 = RelayHandler::with_keypair(relay1.private_key, *relay1.public_key());
        assert!(handler1.handle_packet(&packet));
        
        match handler1.next_event() {
            Some(RelayEvent::Delivered(delivered)) => {
                assert_eq!(delivered.payload, payload);
            }
            other => panic!("Expected Delivered, got {:?}", other),
        }
    }

    #[test]
    fn test_relay_disabled() {
        let mut handler = RelayHandler::new();
        handler.set_relay_enabled(false);
        
        // Try to process a packet that would need forwarding
        // (using invalid packet data - should error anyway)
        let fake_packet = vec![0u8; 100];
        assert!(!handler.handle_packet(&fake_packet));
    }
}
