//! SecureChat Core Library
//! 
//! Provides cryptographic identity generation, key exchange,
//! Signal Protocol encryption, P2P networking, and messaging.

use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// Modules
pub mod network;
pub mod crypto;
pub mod messaging;
pub mod privacy;
pub mod api;
pub mod logger;

// Re-export logger types
pub use logger::{init_logger, CoreLogger};

// Re-export network API types for UniFFI
pub use network::{NetworkManager, NetworkError, create_network_manager};
pub use network::api::{NetworkEvent, PeerInfo};

// Re-export crypto types
pub use crypto::{IdentityKeyPair, PreKeyBundle, SignedPreKey, OneTimePreKey};
pub use crypto::{Session, SessionError, EncryptedMessage};

// Re-export messaging types
pub use messaging::{Message, MessageType, MessageEnvelope};
pub use messaging::{MessagingManager, MessagingError, MessagingEvent, ContactInfo};
pub use messaging::{Contact, ContactStore};

// Re-export API types
pub use api::messaging::{MessagingAPI, OutgoingMessage, MessagingAPIEvent, create_messaging_manager};
pub use api::privacy::{PrivacyAPI, PrivacyAPIEvent, OutgoingOnionPacket, create_privacy_manager};

// Include UniFFI scaffolding
uniffi::include_scaffolding!("securechat_core");

/// A user's cryptographic identity
/// Contains both signing keys (Ed25519) and key exchange keys (X25519)
#[derive(Debug, Clone)]
pub struct Identity {
    pub public_key_hex: String,
    pub private_key_hex: String,
}

/// Result of a Diffie-Hellman key exchange
#[derive(Debug, Clone)]
pub struct SharedSecret {
    pub secret_hex: String,
}

/// Generate a new cryptographic identity
/// 
/// Creates an Ed25519 keypair for signing and identity verification.
/// The keys are returned as hex strings for easy storage/transmission.
pub fn generate_identity() -> Identity {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    
    Identity {
        public_key_hex: hex::encode(verifying_key.as_bytes()),
        private_key_hex: hex::encode(signing_key.to_bytes()),
    }
}

/// Get the public key as a hex string
pub fn get_public_key_hex(identity: &Identity) -> String {
    identity.public_key_hex.clone()
}

/// Get a human-readable fingerprint of the public key
/// 
/// Returns a truncated SHA-256 hash formatted as groups of 4 hex chars
/// Example: "A1B2-C3D4-E5F6-G7H8"
pub fn get_public_key_fingerprint(identity: &Identity) -> String {
    let bytes = hex::decode(&identity.public_key_hex).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    
    // Take first 8 bytes (16 hex chars) and format nicely
    let hex_str = hex::encode(&hash[..8]).to_uppercase();
    let chunks: Vec<&str> = hex_str
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    
    chunks.join("-")
}

/// Perform X25519 Diffie-Hellman key exchange
/// 
/// Takes your identity and their public key, returns a shared secret
/// that both parties can derive independently.
pub fn perform_key_exchange(my_identity: &Identity, their_public_key_hex: String) -> SharedSecret {
    // Convert our private key to X25519 format
    // Note: In production, we'd have separate X25519 keys
    let my_private_bytes: [u8; 32] = hex::decode(&my_identity.private_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    
    let their_public_bytes: [u8; 32] = hex::decode(&their_public_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    
    let my_secret = StaticSecret::from(my_private_bytes);
    let their_public = PublicKey::from(their_public_bytes);
    
    let shared = my_secret.diffie_hellman(&their_public);
    
    SharedSecret {
        secret_hex: hex::encode(shared.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let identity = generate_identity();
        assert_eq!(identity.public_key_hex.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(identity.private_key_hex.len(), 64);
    }

    #[test]
    fn test_fingerprint() {
        let identity = generate_identity();
        let fingerprint = get_public_key_fingerprint(&identity);
        // Format: XXXX-XXXX-XXXX-XXXX
        assert_eq!(fingerprint.len(), 19);
        assert!(fingerprint.contains('-'));
    }
    
    #[test]
    fn test_unique_identities() {
        let id1 = generate_identity();
        let id2 = generate_identity();
        assert_ne!(id1.public_key_hex, id2.public_key_hex);
    }
}
