//! Session management for encrypted communications
//!
//! Combines X3DH and Double Ratchet into a complete session API.

use x25519_dalek::PublicKey as X25519PublicKey;
use serde::{Serialize, Deserialize};

use crate::crypto::keys::{IdentityKeyPair, SignedPreKey, OneTimePreKey, PreKeyBundle};
use crate::crypto::x3dh::{X3DH, X3DHError};
use crate::crypto::ratchet::{DoubleRatchet, EncryptedPayload, RatchetError};

/// A secure messaging session with a peer
pub struct Session {
    /// Our identity
    local_identity: IdentityKeyPair,
    /// Remote identity public key
    remote_identity: X25519PublicKey,
    /// Double ratchet state
    ratchet: DoubleRatchet,
    /// Session established flag
    established: bool,
}

impl Session {
    /// Create a new session as the initiator (Alice)
    pub fn initiate(
        local_identity: IdentityKeyPair,
        remote_bundle: &PreKeyBundle,
    ) -> Result<(Self, InitialMessage), SessionError> {
        // Perform X3DH
        let x3dh_session = X3DH::initiate(&local_identity, remote_bundle)
            .map_err(|e| SessionError::X3DH(e))?;
        
        // Initialize double ratchet as Alice
        let ratchet = DoubleRatchet::init_alice(
            x3dh_session.shared_secret(),
            &remote_bundle.signed_prekey,
        );
        
        // Create initial message to send to Bob
        let initial_msg = InitialMessage {
            identity_key: local_identity.public_key(),
            ephemeral_key: x3dh_session.ephemeral_public,
            used_one_time_prekey_id: x3dh_session.used_one_time_prekey_id,
            ratchet_key: ratchet.public_key(),
        };
        
        Ok((Self {
            local_identity,
            remote_identity: remote_bundle.identity_key,
            ratchet,
            established: true,
        }, initial_msg))
    }

    /// Accept a session as the responder (Bob)
    pub fn respond(
        local_identity: IdentityKeyPair,
        signed_prekey: &SignedPreKey,
        one_time_prekey: Option<&OneTimePreKey>,
        initial_msg: &InitialMessage,
    ) -> Result<Self, SessionError> {
        // Perform X3DH response
        let x3dh_session = X3DH::respond(
            &local_identity,
            signed_prekey,
            one_time_prekey,
            &initial_msg.identity_key,
            &initial_msg.ephemeral_key,
        ).map_err(|e| SessionError::X3DH(e))?;
        
        // Initialize double ratchet as Bob
        // Pass Alice's ratchet key so Bob can create his sending chain immediately
        let ratchet = DoubleRatchet::init_bob(
            x3dh_session.shared_secret(),
            signed_prekey.private_key(),
            &initial_msg.ratchet_key,
        );
        
        Ok(Self {
            local_identity,
            remote_identity: initial_msg.identity_key,
            ratchet,
            established: true,
        })
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage, SessionError> {
        if !self.established {
            return Err(SessionError::NotEstablished);
        }
        
        let payload = self.ratchet.encrypt(plaintext)
            .map_err(|e| SessionError::Ratchet(e))?;
        
        Ok(EncryptedMessage {
            header_dh_public: payload.header.dh_public.to_bytes(),
            header_prev_chain_length: payload.header.prev_chain_length,
            header_message_number: payload.header.message_number,
            ciphertext: payload.ciphertext,
        })
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>, SessionError> {
        if !self.established {
            return Err(SessionError::NotEstablished);
        }
        
        let dh_public = X25519PublicKey::from(message.header_dh_public);
        
        let payload = EncryptedPayload {
            header: crate::crypto::ratchet::MessageHeader {
                dh_public,
                prev_chain_length: message.header_prev_chain_length,
                message_number: message.header_message_number,
            },
            ciphertext: message.ciphertext.clone(),
        };
        
        self.ratchet.decrypt(&payload)
            .map_err(|e| SessionError::Ratchet(e))
    }

    /// Get the remote peer's identity key
    pub fn remote_identity(&self) -> &X25519PublicKey {
        &self.remote_identity
    }

    /// Check if session is established
    pub fn is_established(&self) -> bool {
        self.established
    }
}

/// Initial message sent to establish a session
#[derive(Clone, Debug)]
pub struct InitialMessage {
    /// Sender's identity key
    pub identity_key: X25519PublicKey,
    /// Ephemeral key from X3DH
    pub ephemeral_key: X25519PublicKey,
    /// Used one-time prekey ID (if any)
    pub used_one_time_prekey_id: Option<u32>,
    /// Initial ratchet public key
    pub ratchet_key: X25519PublicKey,
}

impl InitialMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(100);
        bytes.extend_from_slice(self.identity_key.as_bytes());
        bytes.extend_from_slice(self.ephemeral_key.as_bytes());
        bytes.extend_from_slice(self.ratchet_key.as_bytes());
        match self.used_one_time_prekey_id {
            Some(id) => {
                bytes.push(1);
                bytes.extend_from_slice(&id.to_le_bytes());
            }
            None => bytes.push(0),
        }
        bytes
    }
}

/// Encrypted message structure (serializable)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// DH public key from header
    pub header_dh_public: [u8; 32],
    /// Previous chain length
    pub header_prev_chain_length: u32,
    /// Message number
    pub header_message_number: u32,
    /// Encrypted content
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SessionError> {
        serde_json::from_slice(bytes)
            .map_err(|_| SessionError::DeserializationFailed)
    }
}

/// Session errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum SessionError {
    #[error("X3DH error: {0}")]
    X3DH(#[from] X3DHError),
    #[error("Ratchet error: {0}")]
    Ratchet(#[from] RatchetError),
    #[error("Session not established")]
    NotEstablished,
    #[error("Deserialization failed")]
    DeserializationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_establishment() {
        // Alice's identity
        let alice_identity = IdentityKeyPair::generate();
        
        // Bob's identity and prekeys
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity);
        let bob_one_time_prekey = OneTimePreKey::generate(1);
        
        // Bob publishes bundle
        let bob_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_signed_prekey,
            Some(&bob_one_time_prekey),
        );
        
        // Alice initiates session
        let (mut alice_session, initial_msg) = Session::initiate(
            alice_identity,
            &bob_bundle,
        ).unwrap();
        
        // Bob accepts session
        let mut bob_session = Session::respond(
            bob_identity,
            &bob_signed_prekey,
            Some(&bob_one_time_prekey),
            &initial_msg,
        ).unwrap();
        
        // Both sessions should be established
        assert!(alice_session.is_established());
        assert!(bob_session.is_established());
        
        // Test encryption/decryption
        let msg = b"Hello Bob!";
        let encrypted = alice_session.encrypt(msg).unwrap();
        let decrypted = bob_session.decrypt(&encrypted).unwrap();
        assert_eq!(msg.to_vec(), decrypted);
    }

    #[test]
    fn test_bidirectional_messaging() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity);
        
        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_prekey, None);
        
        let (mut alice, initial_msg) = Session::initiate(alice_identity, &bob_bundle).unwrap();
        let mut bob = Session::respond(bob_identity, &bob_signed_prekey, None, &initial_msg).unwrap();
        
        // Multiple messages back and forth
        for i in 0..10 {
            let alice_msg = format!("Alice says: {}", i);
            let enc = alice.encrypt(alice_msg.as_bytes()).unwrap();
            let dec = bob.decrypt(&enc).unwrap();
            assert_eq!(alice_msg.as_bytes(), dec.as_slice());
            
            let bob_msg = format!("Bob replies: {}", i);
            let enc = bob.encrypt(bob_msg.as_bytes()).unwrap();
            let dec = alice.decrypt(&enc).unwrap();
            assert_eq!(bob_msg.as_bytes(), dec.as_slice());
        }
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let msg = EncryptedMessage {
            header_dh_public: [1u8; 32],
            header_prev_chain_length: 5,
            header_message_number: 10,
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        
        let bytes = msg.to_bytes();
        let restored = EncryptedMessage::from_bytes(&bytes).unwrap();
        
        assert_eq!(msg.header_dh_public, restored.header_dh_public);
        assert_eq!(msg.header_prev_chain_length, restored.header_prev_chain_length);
        assert_eq!(msg.header_message_number, restored.header_message_number);
        assert_eq!(msg.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_initial_message_serialization() {
        let identity = IdentityKeyPair::generate();
        let msg = InitialMessage {
            identity_key: identity.public_key(),
            ephemeral_key: identity.public_key(),
            used_one_time_prekey_id: Some(42),
            ratchet_key: identity.public_key(),
        };
        
        let bytes = msg.to_bytes();
        // 32 + 32 + 32 + 1 + 4 = 101 bytes
        assert!(bytes.len() > 96);
    }
}
