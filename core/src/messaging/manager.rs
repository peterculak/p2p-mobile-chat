//! High-level messaging manager integrating network and crypto

use std::collections::VecDeque;

use crate::messaging::protocol::{Message, MessageEnvelope, MessageType};
use crate::messaging::contact::{Contact, ContactStore};
use crate::messaging::handler::{MessageHandler, HandlerError};
use crate::crypto::keys::PreKeyBundle;
use crate::crypto::session::{InitialMessage, SessionError};
use tracing::info;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Events from the messaging system
#[derive(Debug, Clone)]
pub enum MessagingEvent {
    /// New message received
    MessageReceived {
        from_peer_id: String,
        message: Message,
    },
    /// Message sent successfully
    MessageSent {
        to_peer_id: String,
        message_id: String,
    },
    /// Session established with peer
    SessionEstablished {
        peer_id: String,
    },
    /// Delivery receipt received
    DeliveryReceipt {
        peer_id: String,
        message_id: String,
    },
    /// Relay announcement received
    RelayAnnouncement {
        peer_id: String,
        public_key_hex: String,
    },
    /// Onion packet received
    OnionPacketReceived {
        data: Vec<u8>,
    },
    /// Error occurred
    Error {
        message: String,
    },
}

/// Outgoing message to send over network
#[derive(Debug, Clone)]
pub struct OutgoingMessage {
    pub peer_id: String,
    pub data: Vec<u8>,
}

/// Messaging manager
pub struct MessagingManager {
    /// Our peer ID
    peer_id: String,
    /// Contact and session store
    store: ContactStore,
    /// Message handler
    handler: MessageHandler,
    /// Pending outgoing messages
    outgoing: VecDeque<OutgoingMessage>,
    /// Events queue
    events: VecDeque<MessagingEvent>,
}

impl MessagingManager {
    /// Create a new messaging manager
    pub fn new(peer_id: &str) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            store: ContactStore::new(),
            handler: MessageHandler::new(peer_id),
            outgoing: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Get our peer ID
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Get our prekey bundle for sharing with peers
    pub fn get_prekey_bundle(&mut self) -> PreKeyBundle {
        self.store.get_prekey_bundle()
    }

    /// Add a contact
    pub fn add_contact(&mut self, peer_id: &str, name: &str, identity_key: [u8; 32]) {
        let contact = Contact::new(peer_id, name, identity_key);
        self.store.add_contact(contact);
    }

    /// List contacts
    pub fn list_contacts(&self) -> Vec<ContactInfo> {
        self.store.list_contacts().iter().map(|c| ContactInfo {
            peer_id: c.peer_id.clone(),
            name: c.name.clone(),
            session_established: c.session_established,
        }).collect()
    }

    /// Initiate a session with a peer using their prekey bundle
    pub fn initiate_session(&mut self, peer_id: &str, bundle: &PreKeyBundle) -> Result<(), MessagingError> {
        let initial_msg = self.store.initiate_session(peer_id, bundle)
            .map_err(|e: SessionError| MessagingError::Session(e.to_string()))?;
        
        // Create session init message to send
        let init_json = serde_json::to_string(&InitialMessageData {
            identity_key: initial_msg.identity_key.to_bytes(),
            ephemeral_key: initial_msg.ephemeral_key.to_bytes(),
            ratchet_key: initial_msg.ratchet_key.to_bytes(),
            used_otpk_id: initial_msg.used_one_time_prekey_id,
        }).unwrap_or_default();

        let msg = Message::session_init(&init_json);
        let envelope = MessageEnvelope::unencrypted(&self.peer_id, &msg);
        
        self.outgoing.push_back(OutgoingMessage {
            peer_id: peer_id.to_string(),
            data: envelope.to_bytes(),
        });

        self.events.push_back(MessagingEvent::SessionEstablished {
            peer_id: peer_id.to_string(),
        });

        Ok(())
    }

    /// Send a text message to a peer
    pub fn send_message(&mut self, peer_id: &str, text: &str) -> Result<String, MessagingError> {
        let msg = Message::text(text);
        let msg_id = msg.id.clone();
        
        // Require encryption - no unencrypted fallback
        if !self.store.has_session(peer_id) {
            return Err(MessagingError::NoSession);
        }
        
        let envelope = self.handler.prepare_outgoing(&mut self.store, peer_id, &msg)
            .map_err(|e| MessagingError::Handler(e))?;
        
        self.outgoing.push_back(OutgoingMessage {
            peer_id: peer_id.to_string(),
            data: envelope.to_bytes(),
        });

        self.events.push_back(MessagingEvent::MessageSent {
            to_peer_id: peer_id.to_string(),
            message_id: msg_id.clone(),
        });

        // Update last message time
        if let Some(contact) = self.store.get_contact_mut(peer_id) {
            contact.last_message_at = Some(now_ms());
        }

        Ok(msg_id)
    }

    /// Prepare an encrypted message but do not queue it (for onion routing)
    pub fn prepare_encrypted_message(&mut self, peer_id: &str, text: &str) -> Result<(String, Vec<u8>), MessagingError> {
        let msg = Message::text(text);
        let msg_id = msg.id.clone();
        
        if !self.store.has_session(peer_id) {
            return Err(MessagingError::NoSession);
        }
        
        let envelope = self.handler.prepare_outgoing(&mut self.store, peer_id, &msg)
            .map_err(|e| MessagingError::Handler(e))?;
            
        Ok((msg_id, envelope.to_bytes()))
    }

    pub fn handle_incoming(&mut self, _from_peer_id: &str, data: &[u8]) -> Result<(), MessagingError> {
        let envelope = MessageEnvelope::from_bytes(data)
            .map_err(|_| MessagingError::InvalidMessage)?;

        // For all identity and session logic, we MUST use the sender ID from the envelope.
        // The `_from_peer_id` argument is the immediate transport sender (e.g. a relay),
        // but `envelope.sender_peer_id` is the original cryptographic sender.
        let sender_peer_id = &envelope.sender_peer_id;
        
        info!("handle_incoming: envelope from {} (immediate: {}), encrypted: {}", 
            sender_peer_id, _from_peer_id, envelope.encrypted);

        if !envelope.encrypted {
            if let Ok(msg) = Message::from_bytes(&envelope.payload) {
                info!("handle_incoming: Decoded unencrypted message: type={:?}, id={}", 
                    msg.message_type, msg.id);
                
                match msg.message_type {
                    MessageType::SessionInit => {
                        self.handle_session_init(sender_peer_id, &msg)?;
                    }
                    MessageType::Text => {
                         info!("handle_incoming: Received unencrypted TEXT from {}", sender_peer_id);
                         // Allow unencrypted text messages for testing/fallback
                         self.events.push_back(MessagingEvent::MessageReceived {
                            from_peer_id: sender_peer_id.clone(),
                            message: msg.clone(),
                         });
                    }
                    MessageType::RelayAnnouncement => {
                        self.events.push_back(MessagingEvent::RelayAnnouncement {
                            peer_id: sender_peer_id.clone(),
                            public_key_hex: msg.content.clone(),
                        });
                    }
                    MessageType::OnionPacket => {
                        if let Ok(data) = BASE64.decode(&msg.content) {
                            self.events.push_back(MessagingEvent::OnionPacketReceived { data });
                        }
                    }
                    _ => {
                        // Other unencrypted messages not allowed after session
                        return Err(MessagingError::EncryptionRequired);
                    }
                }
            } else {
                return Err(MessagingError::InvalidMessage);
            }
        } else {
            // Encrypted message
            let msg = self.handler.process_incoming(&mut self.store, &envelope)
                .map_err(|e| {
                    info!("handle_incoming: ERROR decrypting message from {}: {}", sender_peer_id, e);
                    MessagingError::Handler(e)
                })?;
            
            info!("handle_incoming: Successfully decrypted message: type={:?}, id={}", 
                msg.message_type, msg.id);
            
            match msg.message_type {
                MessageType::Text => {
                    info!("handle_incoming: Pushing MessageReceived event for {} from ORIGINAL sender {}", msg.id, sender_peer_id);
                    self.events.push_back(MessagingEvent::MessageReceived {
                        from_peer_id: sender_peer_id.clone(),
                        message: msg.clone(),
                    });
                    
                    // Send receipt
                    info!("handle_incoming: Sending receipt for {} to ORIGINAL sender {}", msg.id, sender_peer_id);
                    self.send_receipt(sender_peer_id, &msg.id)?;
                }
                MessageType::Receipt => {
                    self.events.push_back(MessagingEvent::DeliveryReceipt {
                        peer_id: sender_peer_id.clone(),
                        message_id: msg.content.clone(),
                    });
                }
                MessageType::RelayAnnouncement => {
                    self.events.push_back(MessagingEvent::RelayAnnouncement {
                        peer_id: sender_peer_id.clone(),
                        public_key_hex: msg.content.clone(),
                    });
                }
                _ => {}
            }
            
            // Update last message time
            if let Some(contact) = self.store.get_contact_mut(sender_peer_id) {
                contact.last_message_at = Some(now_ms());
            }
        }

        Ok(())
    }

    /// Handle session initialization from another peer
    fn handle_session_init(&mut self, from_peer_id: &str, msg: &Message) -> Result<(), MessagingError> {
        info!("handle_session_init: initiating session with {}", from_peer_id);
        let data: InitialMessageData = serde_json::from_str(&msg.content)
            .map_err(|_| MessagingError::InvalidMessage)?;
        
        let initial_msg = InitialMessage {
            identity_key: x25519_dalek::PublicKey::from(data.identity_key),
            ephemeral_key: x25519_dalek::PublicKey::from(data.ephemeral_key),
            ratchet_key: x25519_dalek::PublicKey::from(data.ratchet_key),
            used_one_time_prekey_id: data.used_otpk_id,
        };

        // Add contact if not exists
        if self.store.get_contact(from_peer_id).is_none() {
            self.store.add_contact(Contact::new(
                from_peer_id,
                from_peer_id, // Use peer ID as name initially
                data.identity_key,
            ));
        }

        self.store.accept_session(from_peer_id, &initial_msg, data.used_otpk_id)
            .map_err(|e: SessionError| MessagingError::Session(e.to_string()))?;

        self.events.push_back(MessagingEvent::SessionEstablished {
            peer_id: from_peer_id.to_string(),
        });

        Ok(())
    }

    /// Send a delivery receipt
    fn send_receipt(&mut self, peer_id: &str, message_id: &str) -> Result<(), MessagingError> {
        let msg = Message::receipt(message_id);
        let envelope = self.handler.prepare_outgoing(&mut self.store, peer_id, &msg)
            .map_err(|e| MessagingError::Handler(e))?;
        
        self.outgoing.push_back(OutgoingMessage {
            peer_id: peer_id.to_string(),
            data: envelope.to_bytes(),
        });

        Ok(())
    }

    /// Get next outgoing message to send over network
    pub fn next_outgoing(&mut self) -> Option<OutgoingMessage> {
        self.outgoing.pop_front()
    }

    /// Get next event
    pub fn next_event(&mut self) -> Option<MessagingEvent> {
        self.events.pop_front()
    }

    /// Check if we have a session with a peer
    pub fn has_session(&self, peer_id: &str) -> bool {
        self.store.has_session(peer_id)
    }
}

/// Serializable contact info for FFI
#[derive(Debug, Clone)]
pub struct ContactInfo {
    pub peer_id: String,
    pub name: String,
    pub session_established: bool,
}

/// Serializable initial message data
#[derive(serde::Serialize, serde::Deserialize)]
struct InitialMessageData {
    identity_key: [u8; 32],
    ephemeral_key: [u8; 32],
    ratchet_key: [u8; 32],
    used_otpk_id: Option<u32>,
}

/// Messaging errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum MessagingError {
    #[error("No session with peer")]
    NoSession,
    #[error("Session error: {0}")]
    Session(String),
    #[error("Handler error: {0}")]
    Handler(#[from] HandlerError),
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Encryption required for this message type")]
    EncryptionRequired,
    #[error("Network error: {0}")]
    Network(String),
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

    #[test]
    fn test_messaging_manager_creation() {
        let manager = MessagingManager::new("peer123");
        assert_eq!(manager.peer_id(), "peer123");
        assert!(manager.list_contacts().is_empty());
    }

    #[test]
    fn test_add_contact() {
        let mut manager = MessagingManager::new("peer123");
        manager.add_contact("other_peer", "Alice", [1u8; 32]);
        
        let contacts = manager.list_contacts();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].name, "Alice");
    }

    #[test]
    fn test_full_messaging_flow() {
        // Alice
        let mut alice = MessagingManager::new("alice_peer");
        
        // Bob
        let mut bob = MessagingManager::new("bob_peer");
        
        // Add contacts
        alice.add_contact("bob_peer", "Bob", [1u8; 32]);
        bob.add_contact("alice_peer", "Alice", [2u8; 32]);
        
        // Alice initiates session with Bob's bundle
        let bob_bundle = bob.get_prekey_bundle();
        alice.initiate_session("bob_peer", &bob_bundle).unwrap();
        
        // Get the outgoing session init message
        let session_init = alice.next_outgoing().unwrap();
        assert_eq!(session_init.peer_id, "bob_peer");
        
        // Bob receives and processes
        bob.handle_incoming("alice_peer", &session_init.data).unwrap();
        
        // Both should have sessions
        assert!(alice.has_session("bob_peer"));
        assert!(bob.has_session("alice_peer"));
        
        // Alice sends a message
        let msg_id = alice.send_message("bob_peer", "Hello Bob!").unwrap();
        assert!(!msg_id.is_empty());
        
        // Get outgoing
        let encrypted = alice.next_outgoing().unwrap();
        
        // Bob receives
        bob.handle_incoming("alice_peer", &encrypted.data).unwrap();
        
        // Bob should have received SessionEstablished event first
        let event = bob.next_event();
        assert!(matches!(event, Some(MessagingEvent::SessionEstablished { .. })));
        
        // Then MessageReceived
        let event = bob.next_event();
        assert!(matches!(event, Some(MessagingEvent::MessageReceived { .. })));
    }

    #[test]
    fn test_bidirectional_messaging() {
        let mut alice = MessagingManager::new("alice");
        let mut bob = MessagingManager::new("bob");
        
        alice.add_contact("bob", "Bob", [1u8; 32]);
        bob.add_contact("alice", "Alice", [2u8; 32]);
        
        // Session setup
        let bob_bundle = bob.get_prekey_bundle();
        alice.initiate_session("bob", &bob_bundle).unwrap();
        let init = alice.next_outgoing().unwrap();
        bob.handle_incoming("alice", &init.data).unwrap();
        
        // Multiple messages
        for i in 0..3 {
            // Alice -> Bob
            alice.send_message("bob", &format!("Msg {}", i)).unwrap();
            let out = alice.next_outgoing().unwrap();
            bob.handle_incoming("alice", &out.data).unwrap();
            
            // Bob -> Alice
            bob.send_message("alice", &format!("Reply {}", i)).unwrap();
            let out = bob.next_outgoing().unwrap();
            alice.handle_incoming("bob", &out.data).unwrap();
        }
    }
}
