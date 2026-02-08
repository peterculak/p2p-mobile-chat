//! Message protocol definitions
//!
//! Defines the wire format for P2P messages.

use serde::{Serialize, Deserialize};
use crate::crypto::session::EncryptedMessage;

/// Message types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageType {
    /// Initial session establishment
    SessionInit,
    /// Session acceptance
    SessionAccept,
    /// Regular text message
    Text,
    /// Delivery receipt
    Receipt,
    /// Typing indicator
    Typing,
    /// Key exchange request
    KeyExchange,
}

/// Plaintext message content
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    /// Message ID (random UUID)
    pub id: String,
    /// Message type
    pub message_type: MessageType,
    /// Timestamp (Unix ms)
    pub timestamp: u64,
    /// Content (type-dependent)
    pub content: String,
}

impl Message {
    /// Create a new text message
    pub fn text(content: &str) -> Self {
        Self {
            id: uuid(),
            message_type: MessageType::Text,
            timestamp: now_ms(),
            content: content.to_string(),
        }
    }

    /// Create a session init message with prekey bundle
    pub fn session_init(bundle_json: &str) -> Self {
        Self {
            id: uuid(),
            message_type: MessageType::SessionInit,
            timestamp: now_ms(),
            content: bundle_json.to_string(),
        }
    }

    /// Create a session accept message
    pub fn session_accept(initial_msg_json: &str) -> Self {
        Self {
            id: uuid(),
            message_type: MessageType::SessionAccept,
            timestamp: now_ms(),
            content: initial_msg_json.to_string(),
        }
    }

    /// Create a delivery receipt
    pub fn receipt(message_id: &str) -> Self {
        Self {
            id: uuid(),
            message_type: MessageType::Receipt,
            timestamp: now_ms(),
            content: message_id.to_string(),
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidFormat)
    }
}

/// Message envelope for transport (includes encryption)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    /// Protocol version
    pub version: u8,
    /// Sender's peer ID
    pub sender_peer_id: String,
    /// Is this encrypted?
    pub encrypted: bool,
    /// Encrypted payload (if encrypted) or raw message JSON
    pub payload: Vec<u8>,
    /// Encrypted message header (if encrypted)
    pub encrypted_header: Option<EncryptedMessageHeader>,
}

/// Header for encrypted messages
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedMessageHeader {
    pub dh_public: [u8; 32],
    pub prev_chain_length: u32,
    pub message_number: u32,
}

impl MessageEnvelope {
    /// Create an unencrypted envelope (for session init)
    pub fn unencrypted(sender_peer_id: &str, message: &Message) -> Self {
        Self {
            version: 1,
            sender_peer_id: sender_peer_id.to_string(),
            encrypted: false,
            payload: message.to_bytes(),
            encrypted_header: None,
        }
    }

    /// Create an encrypted envelope
    pub fn encrypted(sender_peer_id: &str, encrypted_msg: &EncryptedMessage) -> Self {
        Self {
            version: 1,
            sender_peer_id: sender_peer_id.to_string(),
            encrypted: true,
            payload: encrypted_msg.ciphertext.clone(),
            encrypted_header: Some(EncryptedMessageHeader {
                dh_public: encrypted_msg.header_dh_public,
                prev_chain_length: encrypted_msg.header_prev_chain_length,
                message_number: encrypted_msg.header_message_number,
            }),
        }
    }

    /// Serialize to bytes for transport
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from transport bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidFormat)
    }

    /// Convert to EncryptedMessage for decryption
    pub fn to_encrypted_message(&self) -> Option<EncryptedMessage> {
        self.encrypted_header.as_ref().map(|h| EncryptedMessage {
            header_dh_public: h.dh_public,
            header_prev_chain_length: h.prev_chain_length,
            header_message_number: h.message_number,
            ciphertext: self.payload.clone(),
        })
    }
}

/// Protocol errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProtocolError {
    #[error("Invalid message format")]
    InvalidFormat,
    #[error("Unknown protocol version")]
    UnknownVersion,
    #[error("Encryption required")]
    EncryptionRequired,
}

/// Generate a simple UUID
fn uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

/// Current timestamp in milliseconds
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

    #[test]
    fn test_message_creation() {
        let msg = Message::text("Hello world");
        assert_eq!(msg.message_type, MessageType::Text);
        assert_eq!(msg.content, "Hello world");
        assert!(!msg.id.is_empty());
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::text("Test message");
        let bytes = msg.to_bytes();
        let restored = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg.id, restored.id);
        assert_eq!(msg.content, restored.content);
    }

    #[test]
    fn test_envelope_unencrypted() {
        let msg = Message::text("Hello");
        let envelope = MessageEnvelope::unencrypted("peer123", &msg);
        
        assert!(!envelope.encrypted);
        assert_eq!(envelope.sender_peer_id, "peer123");
        assert_eq!(envelope.version, 1);
    }

    #[test]
    fn test_envelope_serialization() {
        let msg = Message::text("Hello");
        let envelope = MessageEnvelope::unencrypted("peer123", &msg);
        
        let bytes = envelope.to_bytes();
        let restored = MessageEnvelope::from_bytes(&bytes).unwrap();
        
        assert_eq!(envelope.sender_peer_id, restored.sender_peer_id);
        assert_eq!(envelope.encrypted, restored.encrypted);
    }
}
