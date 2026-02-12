//! Sphinx packet wrapper for onion routing
//!
//! Wraps the sphinx-packet crate to provide a simpler API for our use case.

use sphinx_packet::{
    SphinxPacket,
    route::{Node, NodeAddressBytes, Destination, DestinationAddressBytes},
    header::delays::Delay,
    packet::builder::SphinxPacketBuilder,
    header::HEADER_SIZE,
    payload::PAYLOAD_OVERHEAD_SIZE,
    crypto::PublicKey as SphinxPublicKey,
};
use x25519_dalek::{StaticSecret, PublicKey};
use rand::rngs::OsRng;
use thiserror::Error;
use tracing::info;

/// Fixed packet size for traffic analysis resistance
/// Must match obfuscation::FIXED_PACKET_SIZE
pub const SPHINX_PACKET_SIZE: usize = crate::privacy::obfuscation::FIXED_PACKET_SIZE;

/// Maximum plaintext size that fits into the fixed packet size.
/// We reserve 4 bytes for our length prefix.
pub const MAX_PLAINTEXT_SIZE: usize =
    SPHINX_PACKET_SIZE - HEADER_SIZE - PAYLOAD_OVERHEAD_SIZE - 4;

/// Maximum address size for routing (32 bytes for peer ID)
/// Note: We must use the raw 32-byte Ed25519 public key, not the full string
pub const ADDRESS_SIZE: usize = 32;

/// Number of hops in a circuit
pub const NUM_HOPS: usize = 1;

// Helper to get raw 32-byte pubkey from PeerId string
pub fn peer_id_to_bytes(peer_id_str: &str) -> Option<Vec<u8>> {
    use std::str::FromStr;
    use libp2p::PeerId;
    
    if let Ok(peer_id) = PeerId::from_str(peer_id_str) {
        // For Ed25519 (multihash code 0x00), the digest is the pubkey
        let multihash = peer_id.as_ref();
        if multihash.code() == 0x00 || multihash.code() == 0xed { 
             let bytes = multihash.to_bytes();
             // Debug info: [0, 36, 8, 1, 18, 32, ...]
             // 0x00 = Identity Code
             // 0x24 = Digest Len (36)
             // 0x08, 0x01 = Protobuf Field 1 (Type: Ed25519)
             // 0x12, 0x20 = Protobuf Field 2 (Data: 32 bytes)
             
             if bytes.len() == 38 && bytes[0] == 0x00 && bytes[1] == 36 && 
                bytes[2] == 0x08 && bytes[3] == 0x01 && bytes[4] == 0x12 && bytes[5] == 0x20 {
                  return Some(bytes[6..38].to_vec());
             }
             
             // Initial check for raw key (if some other format used):
             if bytes.len() == 34 && bytes[0] == 0x00 && bytes[1] == 32 {
                  return Some(bytes[2..].to_vec());
             }
        }
    }
    None
}

// Helper to reconstruct PeerId string from 32-byte pubkey
pub fn bytes_to_peer_id(bytes: &[u8]) -> String {
    use libp2p::PeerId;
    use libp2p::identity::PublicKey;
    use libp2p::identity::ed25519;
    
    if bytes.len() == 32 {
        if let Ok(pubkey) = ed25519::PublicKey::try_from_bytes(bytes) {
             let libp2p_pubkey = PublicKey::from(pubkey);
             return PeerId::from_public_key(&libp2p_pubkey).to_string();
        }
    }
    String::new()
}

/// Errors from sphinx operations
#[derive(Debug, Error)]
pub enum SphinxError {
    #[error("Failed to create packet: {0}")]
    PacketCreation(String),
    #[error("Failed to process packet: {0}")]
    PacketProcessing(String),
    #[error("Invalid route: {0}")]
    InvalidRoute(String),
    #[error("Payload too large: {size} > {max}")]
    PayloadTooLarge { size: usize, max: usize },
}

/// A relay node in the onion route
#[derive(Debug, Clone)]
pub struct RelayNode {
    /// The node's address (peer ID bytes, max 64 bytes)
    pub address: Vec<u8>,
    /// The node's X25519 public key for encryption
    pub public_key: [u8; 32],
}

impl RelayNode {
    /// Create a new relay node
    pub fn new(address: Vec<u8>, public_key: [u8; 32]) -> Self {
        Self { address, public_key }
    }
    
    /// Convert to sphinx-packet's Node type
    fn to_sphinx_node(&self) -> Node {
        // - When registering a relay, we store its Public Key (already have it).
        // - In `to_sphinx_node`, we use the 32-byte Public Key as the address.
        // - In `manager.rs`, when we extract the address (next_peer_id), we get 32 bytes.
        // - We treat these 32 bytes as a Public Key and convert to PeerId.
        
        // But wait, `RelayNode` address is `Vec<u8>`. `manager.rs` populates it from `peer_id.as_bytes()`.
        
        // I'll try to stick to the plan of increasing size first. If compilation fails, I'll switch to using Public Key for addressing.
        
        let mut addr_bytes = [0u8; ADDRESS_SIZE];
        let copy_len = self.address.len().min(ADDRESS_SIZE);
        addr_bytes[..copy_len].copy_from_slice(&self.address[..copy_len]);
        
        Node::new(
            NodeAddressBytes::from_bytes(addr_bytes), // This might fail if trait expects [u8; 32]
            SphinxPublicKey::from(PublicKey::from(self.public_key)),
        )
    }
}

/// Final destination for an onion packet
#[derive(Debug, Clone)]
pub struct OnionDestination {
    /// The destination's address (peer ID bytes)
    pub address: Vec<u8>,
    /// Identifier for this message (for replies)
    pub identifier: [u8; 16],
}

impl OnionDestination {
    pub fn new(address: Vec<u8>) -> Self {
        let mut identifier = [0u8; 16];
        rand::RngCore::fill_bytes(&mut OsRng, &mut identifier);
        Self { address, identifier }
    }
    
    fn to_sphinx_destination(&self) -> Destination {
        let mut addr_bytes = [0u8; ADDRESS_SIZE];
        let copy_len = self.address.len().min(ADDRESS_SIZE);
        addr_bytes[..copy_len].copy_from_slice(&self.address[..copy_len]);
        
        Destination::new(
            DestinationAddressBytes::from_bytes(addr_bytes),
            self.identifier,
        )
    }
}

/// Result of processing an onion packet
#[derive(Debug)]
pub enum ProcessResult {
    /// Forward to next hop
    Forward {
        next_address: Vec<u8>,
        packet_bytes: Vec<u8>,
        delay_ms: u64,
    },
    /// Final destination reached
    Destination {
        /// The intended recipient's address
        destination_address: Vec<u8>,
        payload: Vec<u8>,
        identifier: [u8; 16],
    },
}

/// Create an onion packet with layered encryption
///
/// # Arguments
/// * `payload` - The message payload (max ~900 bytes for 3-hop routes)
/// * `route` - List of relay nodes (should be NUM_HOPS)
/// * `destination` - Final destination
///
/// # Returns
/// The serialized onion packet bytes
pub fn create_onion_packet(
    payload: &[u8],
    route: &[RelayNode],
    destination: &OnionDestination,
) -> Result<Vec<u8>, SphinxError> {
    if payload.len() > MAX_PLAINTEXT_SIZE {
        return Err(SphinxError::PayloadTooLarge {
            size: payload.len(),
            max: MAX_PLAINTEXT_SIZE,
        });
    }
    
    if route.is_empty() {
        return Err(SphinxError::InvalidRoute("Route cannot be empty".into()));
    }
    
    // Convert route to sphinx nodes
    let sphinx_nodes: Vec<Node> = route.iter().map(|n| n.to_sphinx_node()).collect();
    
    // Create delays for each hop (using zero delays for now, will add jitter later)
    let delays: Vec<Delay> = vec![Delay::new_from_millis(0); route.len()];
    
    // Prepend length (4 bytes) to payload for recovery at destination
    let mut message = Vec::with_capacity(4 + payload.len());
    message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    message.extend_from_slice(payload);
    
    // Build the packet using a payload size that yields a fixed packet size
    let payload_size = SPHINX_PACKET_SIZE - HEADER_SIZE;
    let sphinx_dest = destination.to_sphinx_destination();
    let packet = SphinxPacketBuilder::new()
        .with_payload_size(payload_size)
        .build_packet(message, &sphinx_nodes, &sphinx_dest, &delays)
        .map_err(|e| SphinxError::PacketCreation(e.to_string()))?;
    
    Ok(packet.to_bytes())
}

/// Process (unwrap) one layer of an onion packet
///
/// Called by relay nodes to decrypt their layer and forward.
///
/// # Arguments
/// * `packet_bytes` - The encrypted onion packet
/// * `private_key` - This node's X25519 private key
///
/// # Returns
/// ProcessResult indicating whether to forward or deliver
pub fn process_onion_packet(
    packet_bytes: &[u8],
    private_key: &[u8; 32],
) -> Result<ProcessResult, SphinxError> {
    // TRUNCATE the buffer to the canonical Sphinx packet size.
    // This is CRITICAL because manager.rs adds random padding up to 8192 bytes
    // for traffic analysis resistance. Truncation ensures we don't pass garbage
    // to the sphinx-packet decoder which might otherwise corrupt payload recovery.
    let packet_bytes = if packet_bytes.len() > SPHINX_PACKET_SIZE {
        &packet_bytes[..SPHINX_PACKET_SIZE]
    } else {
        packet_bytes
    };

    let packet = SphinxPacket::from_bytes(packet_bytes)
        .map_err(|e| SphinxError::PacketProcessing(e.to_string()))?;
    
    let secret = StaticSecret::from(*private_key);
    let processed = packet.process(&secret)
        .map_err(|e| SphinxError::PacketProcessing(e.to_string()))?;
    
    match processed.data {
        sphinx_packet::ProcessedPacketData::ForwardHop { 
            next_hop_packet, 
            next_hop_address, 
            delay 
        } => {
            let next_addr_bytes = next_hop_address.as_bytes().to_vec();
            info!("Sphinx: Result = FORWARD to next hop ({} bytes)...", next_addr_bytes.len());
            Ok(ProcessResult::Forward {
                next_address: next_addr_bytes,
                packet_bytes: next_hop_packet.to_bytes(),
                delay_ms: delay.to_nanos() / 1_000_000,
            })
        }
        sphinx_packet::ProcessedPacketData::FinalHop { 
            destination, 
            identifier, 
            payload 
        } => {
            info!("Sphinx: Result = FINAL hop reached! Destination in header: {}", hex::encode(destination.as_bytes()));
            // The payload needs to be recovered using recover_plaintext
            match payload.recover_plaintext() {
                Ok(plaintext_bytes) => {
                    // Extract original payload length from first 4 bytes
                    if plaintext_bytes.len() >= 4 {
                        let len = u32::from_be_bytes([
                            plaintext_bytes[0],
                            plaintext_bytes[1],
                            plaintext_bytes[2],
                            plaintext_bytes[3],
                        ]) as usize;
                        
                        let original_payload = if len <= plaintext_bytes.len() - 4 {
                            plaintext_bytes[4..4 + len].to_vec()
                        } else {
                            // Length seems wrong, return everything after header
                            plaintext_bytes[4..].to_vec()
                        };
                        
                        Ok(ProcessResult::Destination {
                            destination_address: destination.as_bytes().to_vec(),
                            payload: original_payload,
                            identifier,
                        })
                    } else {
                        Ok(ProcessResult::Destination {
                            destination_address: destination.as_bytes().to_vec(),
                            payload: plaintext_bytes,
                            identifier,
                        })
                    }
                }
                Err(e) => Err(SphinxError::PacketProcessing(format!("Failed to recover plaintext: {}", e)))
            }
        }
    }
}

/// Generate a new X25519 keypair for relay nodes
pub fn generate_relay_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (secret, public) = generate_relay_keypair();
        assert_ne!(secret, [0u8; 32]);
        assert_ne!(public, [0u8; 32]);
    }

    #[test]
    fn test_create_and_process_single_hop() {
        // Generate a relay node keypair
        let (relay_secret, relay_public) = generate_relay_keypair();
        
        // Create route with one relay
        let relay = RelayNode::new(b"relay1_address".to_vec(), relay_public);
        let destination = OnionDestination::new(b"destination_peer".to_vec());
        
        let payload = b"Hello, onion world!";
        let packet_bytes = create_onion_packet(payload, &[relay], &destination).unwrap();
        
        // Process at relay - should be final hop since only 1 relay
        let result = process_onion_packet(&packet_bytes, &relay_secret).unwrap();
        
        match result {
            ProcessResult::Destination { payload: decrypted, .. } => {
                assert_eq!(&decrypted, payload);
            }
            ProcessResult::Forward { .. } => {
                panic!("Expected destination, got forward");
            }
        }
    }

    #[test]
    fn test_three_hop_circuit() {
        // Generate 3 relay keypairs
        let (secret1, public1) = generate_relay_keypair();
        let (secret2, public2) = generate_relay_keypair();
        let (secret3, public3) = generate_relay_keypair();
        
        let route = vec![
            RelayNode::new(b"relay1".to_vec(), public1),
            RelayNode::new(b"relay2".to_vec(), public2),
            RelayNode::new(b"relay3".to_vec(), public3),
        ];
        
        let destination = OnionDestination::new(b"final_dest".to_vec());
        let payload = b"Secret message through 3 hops!";
        
        // Create packet
        let raw_packet = create_onion_packet(payload, &route, &destination).unwrap();
        
        // Simulate 8KB transport padding as done in manager.rs
        let mut packet_bytes = vec![0u8; 8192];
        packet_bytes[..raw_packet.len()].copy_from_slice(&raw_packet);
        // Fill rest with garbage
        for i in raw_packet.len()..8192 {
            packet_bytes[i] = (i % 256) as u8;
        }
        
        // Process at hop 1
        let result1 = process_onion_packet(&packet_bytes, &secret1).unwrap();
        match result1 {
            ProcessResult::Forward { packet_bytes: next, .. } => {
                packet_bytes = next;
            }
            _ => panic!("Expected forward at hop 1"),
        }
        
        // Process at hop 2
        let result2 = process_onion_packet(&packet_bytes, &secret2).unwrap();
        match result2 {
            ProcessResult::Forward { packet_bytes: next, .. } => {
                packet_bytes = next;
            }
            _ => panic!("Expected forward at hop 2"),
        }
        
        // Process at hop 3 (final)
        let result3 = process_onion_packet(&packet_bytes, &secret3).unwrap();
        match result3 {
            ProcessResult::Destination { payload: decrypted, .. } => {
                assert_eq!(&decrypted, payload);
            }
            _ => panic!("Expected destination at hop 3"),
        }
    }

    #[test]
    fn test_long_address_roundtrip() {
        // Real libp2p peer ID (Ed25519) is ~52 chars
        let long_id = "12D3KooWGe4SnaxudAxkttTEfVmjgBkJG3jXCwBejEgJEi8baFpX";
        let (_, pub_key) = generate_relay_keypair();
        
        // Use helper to convert to 32-byte key
        let addr_bytes = peer_id_to_bytes(long_id).expect("Should parse valid peer ID");
        assert_eq!(addr_bytes.len(), 32);

        let node = RelayNode::new(addr_bytes.clone(), pub_key);
        let sphinx_node = node.to_sphinx_node();
        
        // Extract address from sphinx node
        let extracted_bytes = sphinx_node.address.as_bytes();
        // Since we passed 32 bytes, it should match validly without truncation
        assert_eq!(&extracted_bytes[..32], &addr_bytes[..]);
        
        // And we should be able to reconstruct the ID
        let reconstructed = bytes_to_peer_id(extracted_bytes);
        assert_eq!(reconstructed, long_id);
    }
}
