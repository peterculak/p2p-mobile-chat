//! Circuit building for onion routing
//!
//! Builds multi-hop circuits through relay nodes for anonymous message delivery.

use crate::privacy::sphinx_wrapper::{
    RelayNode, OnionDestination, create_onion_packet, SphinxError, NUM_HOPS,
};
use rand::seq::SliceRandom;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::info;

/// Errors from circuit operations
#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("Not enough relay nodes available: need {need}, have {have}")]
    NotEnoughRelays { need: usize, have: usize },
    #[error("Destination is in the relay set")]
    DestinationInRelays,
    #[error("Sphinx error: {0}")]
    Sphinx(#[from] SphinxError),
    #[error("Circuit expired or invalid")]
    InvalidCircuit,
}

/// A built onion routing circuit
#[derive(Debug, Clone)]
pub struct Circuit {
    /// Unique circuit ID
    pub id: u64,
    /// The relay nodes in order (first = entry, last = exit)
    pub hops: Vec<RelayNode>,
    /// Time when circuit was built
    pub created_at: u64,
}

impl Circuit {
    /// Wrap a message in this circuit's onion layers
    pub fn wrap_message(
        &self,
        payload: &[u8],
        destination: &OnionDestination,
    ) -> Result<Vec<u8>, CircuitError> {
        create_onion_packet(payload, &self.hops, destination)
            .map_err(CircuitError::Sphinx)
    }
    
    /// Get the entry node (first hop) address
    pub fn entry_node(&self) -> Option<&Vec<u8>> {
        self.hops.first().map(|n| &n.address)
    }
}

/// Registry of known relay nodes in the network
#[derive(Debug, Default)]
pub struct RelayRegistry {
    /// Map of peer_id -> relay node info
    relays: HashMap<String, RelayNode>,
}

impl RelayRegistry {
    pub fn new() -> Self {
        Self {
            relays: HashMap::new(),
        }
    }
    
    /// Register a node as a relay
    pub fn register(&mut self, peer_id: String, public_key: [u8; 32]) {
        if let Some(address_bytes) = crate::privacy::sphinx_wrapper::peer_id_to_bytes(&peer_id) {
             let node = RelayNode::new(address_bytes, public_key);
             self.relays.insert(peer_id, node);
        } else {
             // Log error or ignore if not Ed25519
             // For now we just ignore invalid/non-Ed25519 peers as relays
        }
    }
    
    /// Remove a relay
    pub fn unregister(&mut self, peer_id: &str) {
        self.relays.remove(peer_id);
    }
    
    /// Get all available relays
    pub fn get_all(&self) -> Vec<RelayNode> {
        self.relays.values().cloned().collect()
    }
    
    /// Get relay count
    pub fn count(&self) -> usize {
        self.relays.len()
    }
    
    /// Check if a peer is a registered relay
    pub fn is_relay(&self, peer_id: &str) -> bool {
        self.relays.contains_key(peer_id)
    }
}

/// Builds and manages onion routing circuits
pub struct CircuitBuilder {
    /// Registry of known relay nodes
    relay_registry: Arc<RwLock<RelayRegistry>>,
    /// Next circuit ID
    next_circuit_id: u64,
    /// Number of hops to use
    num_hops: usize,
}

impl CircuitBuilder {
    pub fn new(relay_registry: Arc<RwLock<RelayRegistry>>) -> Self {
        Self {
            relay_registry,
            next_circuit_id: 1,
            num_hops: NUM_HOPS,
        }
    }
    
    /// Set the number of hops for circuits
    pub fn with_hops(mut self, num_hops: usize) -> Self {
        self.num_hops = num_hops;
        self
    }
    
    pub fn build_circuit(&mut self, exclude_peer_id: Option<&str>) -> Result<Circuit, CircuitError> {
        let registry = self.relay_registry.read().unwrap();
        
        let exclude_bytes = exclude_peer_id.and_then(|id| crate::privacy::sphinx_wrapper::peer_id_to_bytes(id));
        
        // Get available relays, excluding destination if specified
        let mut available: Vec<RelayNode> = registry
            .get_all()
            .into_iter()
            .filter(|r| {
                if let Some(ref exclude) = exclude_bytes {
                    let is_match = &r.address == exclude;
                    if is_match {
                        info!("Excluding destination from relay set: {:?}", exclude_peer_id);
                    }
                    !is_match
                } else {
                    true
                }
            })
            .collect();
        
        info!("Available relays for circuit: {} (requested: {})", available.len(), self.num_hops);

        
        if available.len() < self.num_hops {
            return Err(CircuitError::NotEnoughRelays {
                need: self.num_hops,
                have: available.len(),
            });
        }
        
        // Randomly select hops
        available.shuffle(&mut OsRng);
        let hops: Vec<RelayNode> = available.into_iter().take(self.num_hops).collect();
        
        let circuit = Circuit {
            id: self.next_circuit_id,
            hops,
            created_at: now_ms(),
        };
        
        self.next_circuit_id += 1;
        
        Ok(circuit)
    }
    
    /// Build a circuit with specific relay nodes (for testing)
    pub fn build_with_relays(&mut self, relays: Vec<RelayNode>) -> Circuit {
        let circuit = Circuit {
            id: self.next_circuit_id,
            hops: relays,
            created_at: now_ms(),
        };
        self.next_circuit_id += 1;
        circuit
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::sphinx_wrapper::generate_relay_keypair;

    #[test]
    fn test_relay_registry() {
        let mut registry = RelayRegistry::new();
        
        let (_, public1) = generate_relay_keypair();
        let (_, public2) = generate_relay_keypair();
        
        registry.register("peer1".to_string(), public1);
        registry.register("peer2".to_string(), public2);
        
        assert_eq!(registry.count(), 2);
        assert!(registry.is_relay("peer1"));
        assert!(!registry.is_relay("peer3"));
        
        registry.unregister("peer1");
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_build_circuit() {
        let registry = Arc::new(RwLock::new(RelayRegistry::new()));
        
        // Add 3 relays
        for i in 0..3 {
            let (_, public) = generate_relay_keypair();
            registry.write().unwrap().register(format!("peer{}", i), public);
        }
        
        let mut builder = CircuitBuilder::new(registry.clone());
        let circuit = builder.build_circuit(None).unwrap();
        
        assert_eq!(circuit.hops.len(), 3);
        assert_eq!(circuit.id, 1);
    }

    #[test]
    fn test_build_circuit_not_enough_relays() {
        let registry = Arc::new(RwLock::new(RelayRegistry::new()));
        
        // Add only 2 relays
        for i in 0..2 {
            let (_, public) = generate_relay_keypair();
            registry.write().unwrap().register(format!("peer{}", i), public);
        }
        
        let mut builder = CircuitBuilder::new(registry.clone());
        let result = builder.build_circuit(None);
        
        assert!(matches!(result, Err(CircuitError::NotEnoughRelays { .. })));
    }

    #[test]
    fn test_circuit_excludes_destination() {
        let registry = Arc::new(RwLock::new(RelayRegistry::new()));
        
        // Add 4 relays
        for i in 0..4 {
            let (_, public) = generate_relay_keypair();
            registry.write().unwrap().register(format!("peer{}", i), public);
        }
        
        let mut builder = CircuitBuilder::new(registry.clone());
        let circuit = builder.build_circuit(Some("peer0")).unwrap();
        
        // Verify peer0 is not in the circuit
        for hop in &circuit.hops {
            assert_ne!(String::from_utf8_lossy(&hop.address), "peer0");
        }
    }
}
