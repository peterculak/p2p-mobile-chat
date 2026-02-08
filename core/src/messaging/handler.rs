//! Message handler for processing incoming and outgoing messages

use crate::crypto::session::SessionError;
use crate::messaging::protocol::{Message, MessageEnvelope};
use crate::messaging::contact::ContactStore;

/// Handles message encryption/decryption and routing
pub struct MessageHandler {
    /// Our peer ID
    peer_id: String,
}

impl MessageHandler {
    pub fn new(peer_id: &str) -> Self {
        Self {
            peer_id: peer_id.to_string(),
        }
    }

    /// Prepare a message for sending (encrypt if session exists)
    pub fn prepare_outgoing(
        &self,
        store: &mut ContactStore,
        recipient_peer_id: &str,
        message: &Message,
    ) -> Result<MessageEnvelope, HandlerError> {
        if store.has_session(recipient_peer_id) {
            // Encrypt with existing session
            let session = store.get_session(recipient_peer_id)
                .ok_or(HandlerError::NoSession)?;
            
            let plaintext = message.to_bytes();
            let encrypted = session.encrypt(&plaintext)
                .map_err(|e: SessionError| HandlerError::Encryption(e.to_string()))?;
            
            Ok(MessageEnvelope::encrypted(&self.peer_id, &encrypted))
        } else {
            // Send unencrypted (only for session init messages)
            Ok(MessageEnvelope::unencrypted(&self.peer_id, message))
        }
    }

    /// Process an incoming message envelope
    pub fn process_incoming(
        &self,
        store: &mut ContactStore,
        envelope: &MessageEnvelope,
    ) -> Result<Message, HandlerError> {
        if envelope.encrypted {
            // Decrypt with session
            let session = store.get_session(&envelope.sender_peer_id)
                .ok_or(HandlerError::NoSession)?;
            
            let encrypted_msg = envelope.to_encrypted_message()
                .ok_or(HandlerError::InvalidMessage)?;
            
            let plaintext = session.decrypt(&encrypted_msg)
                .map_err(|e: SessionError| HandlerError::Decryption(e.to_string()))?;
            
            Message::from_bytes(&plaintext)
                .map_err(|_| HandlerError::InvalidMessage)
        } else {
            // Unencrypted message (session init)
            Message::from_bytes(&envelope.payload)
                .map_err(|_| HandlerError::InvalidMessage)
        }
    }
}

/// Handler errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum HandlerError {
    #[error("No session with peer")]
    NoSession,
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Invalid message format")]
    InvalidMessage,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::contact::Contact;
    use crate::messaging::protocol::MessageType;

    #[test]
    fn test_unencrypted_message_flow() {
        let mut store = ContactStore::new();
        let handler = MessageHandler::new("my_peer");
        
        let msg = Message::text("Hello");
        let envelope = handler.prepare_outgoing(&mut store, "other_peer", &msg).unwrap();
        
        // Should be unencrypted since no session
        assert!(!envelope.encrypted);
    }

    #[test]
    fn test_encrypted_message_flow() {
        // Alice's side
        let mut alice_store = ContactStore::new();
        let alice_handler = MessageHandler::new("alice_peer");
        
        // Bob's side
        let mut bob_store = ContactStore::new();
        let bob_handler = MessageHandler::new("bob_peer");
        
        // Add contacts
        alice_store.add_contact(Contact::new("bob_peer", "Bob", 
            bob_store.identity().public_key_bytes()));
        bob_store.add_contact(Contact::new("alice_peer", "Alice",
            alice_store.identity().public_key_bytes()));
        
        // Establish session
        let bob_bundle = bob_store.get_prekey_bundle();
        let initial_msg = alice_store.initiate_session("bob_peer", &bob_bundle).unwrap();
        bob_store.accept_session("alice_peer", &initial_msg, initial_msg.used_one_time_prekey_id).unwrap();
        
        // Alice sends encrypted message
        let msg = Message::text("Secret message");
        let envelope = alice_handler.prepare_outgoing(&mut alice_store, "bob_peer", &msg).unwrap();
        
        assert!(envelope.encrypted);
        
        // Bob decrypts
        let decrypted = bob_handler.process_incoming(&mut bob_store, &envelope).unwrap();
        assert_eq!(decrypted.content, "Secret message");
        assert_eq!(decrypted.message_type, MessageType::Text);
    }

    #[test]
    fn test_bidirectional_encrypted_messages() {
        let mut alice_store = ContactStore::new();
        let alice_handler = MessageHandler::new("alice");
        
        let mut bob_store = ContactStore::new();
        let bob_handler = MessageHandler::new("bob");
        
        // Setup
        alice_store.add_contact(Contact::new("bob", "Bob", bob_store.identity().public_key_bytes()));
        bob_store.add_contact(Contact::new("alice", "Alice", alice_store.identity().public_key_bytes()));
        
        let bob_bundle = bob_store.get_prekey_bundle();
        let init = alice_store.initiate_session("bob", &bob_bundle).unwrap();
        bob_store.accept_session("alice", &init, init.used_one_time_prekey_id).unwrap();
        
        // Multiple messages both directions
        for i in 0..5 {
            // Alice -> Bob
            let msg = Message::text(&format!("Alice msg {}", i));
            let env = alice_handler.prepare_outgoing(&mut alice_store, "bob", &msg).unwrap();
            let dec = bob_handler.process_incoming(&mut bob_store, &env).unwrap();
            assert_eq!(dec.content, format!("Alice msg {}", i));
            
            // Bob -> Alice
            let msg = Message::text(&format!("Bob msg {}", i));
            let env = bob_handler.prepare_outgoing(&mut bob_store, "alice", &msg).unwrap();
            let dec = alice_handler.process_incoming(&mut alice_store, &env).unwrap();
            assert_eq!(dec.content, format!("Bob msg {}", i));
        }
    }
}
