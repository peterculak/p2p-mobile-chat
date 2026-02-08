use crate::messaging::manager::{MessagingManager, MessagingEvent as InternalEvent, OutgoingMessage as InternalOutgoing, ContactInfo};
use crate::crypto::keys::PreKeyBundle;
use std::sync::{Arc, Mutex};

/// Messaging manager exposed to FFI
pub struct MessagingAPI {
    manager: Arc<Mutex<MessagingManager>>,
}

#[derive(Debug, Clone)]
pub struct OutgoingMessage {
    pub peer_id: String,
    pub data: Vec<u8>,
}

impl From<InternalOutgoing> for OutgoingMessage {
    fn from(m: InternalOutgoing) -> Self {
        Self {
            peer_id: m.peer_id,
            data: m.data,
        }
    }
}

#[derive(Debug, Clone)]
pub enum MessagingAPIEvent {
    MessageReceived {
        from_peer_id: String,
        text: String,
        id: String,
    },
    MessageSent {
        to_peer_id: String,
        message_id: String,
    },
    SessionEstablished {
        peer_id: String,
    },
    DeliveryReceipt {
        peer_id: String,
        message_id: String,
    },
    RelayAnnouncement {
        peer_id: String,
        public_key_hex: String,
    },
    OnionPacketReceived {
        data: Vec<u8>,
    },
    Error {
        message: String,
    },
}

impl From<InternalEvent> for MessagingAPIEvent {
    fn from(e: InternalEvent) -> Self {
        match e {
            InternalEvent::MessageReceived { from_peer_id, message } => {
                MessagingAPIEvent::MessageReceived {
                    from_peer_id,
                    text: message.content, // Assuming text content for now
                    id: message.id,
                }
            },
            InternalEvent::MessageSent { to_peer_id, message_id } => {
                MessagingAPIEvent::MessageSent { to_peer_id, message_id }
            },
            InternalEvent::SessionEstablished { peer_id } => {
                MessagingAPIEvent::SessionEstablished { peer_id }
            },
            InternalEvent::DeliveryReceipt { peer_id, message_id } => {
                MessagingAPIEvent::DeliveryReceipt { peer_id, message_id }
            },
            InternalEvent::RelayAnnouncement { peer_id, public_key_hex } => {
                MessagingAPIEvent::RelayAnnouncement { peer_id, public_key_hex }
            },
            InternalEvent::OnionPacketReceived { data } => {
                MessagingAPIEvent::OnionPacketReceived { data }
            },
            InternalEvent::Error { message } => {
                MessagingAPIEvent::Error { message }
            },
        }
    }
}

impl MessagingAPI {
    pub fn new(peer_id: String) -> Self {
        Self {
            manager: Arc::new(Mutex::new(MessagingManager::new(&peer_id))),
        }
    }
    pub fn get_prekey_bundle(&self) -> String {
        let mut manager = self.manager.lock().unwrap();
        let bundle = manager.get_prekey_bundle();
        serde_json::to_string(&bundle).unwrap_or_default()
    }

    pub fn add_contact(&self, peer_id: String, name: String, identity_key: Vec<u8>) {
        if identity_key.len() != 32 {
            return;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&identity_key);
        self.manager.lock().unwrap().add_contact(&peer_id, &name, key);
    }

    pub fn initiate_session(&self, peer_id: String, bundle_json: String) -> Result<(), String> {
        let bundle: PreKeyBundle = serde_json::from_str(&bundle_json)
            .map_err(|e| format!("Invalid bundle JSON: {}", e))?;
        self.manager.lock().unwrap().initiate_session(&peer_id, &bundle)
            .map_err(|e| e.to_string())
    }

    pub fn send_message(&self, peer_id: String, text: String) -> Result<String, String> {
        self.manager.lock().unwrap().send_message(&peer_id, &text)
            .map_err(|e| e.to_string())
    }

    pub fn handle_incoming(&self, from_peer_id: String, data: Vec<u8>) -> Result<(), String> {
        self.manager.lock().unwrap().handle_incoming(&from_peer_id, &data)
            .map_err(|e| e.to_string())
    }

    pub fn next_outgoing(&self) -> Option<OutgoingMessage> {
        self.manager.lock().unwrap().next_outgoing().map(|m| m.into())
    }

    pub fn next_event(&self) -> Option<MessagingAPIEvent> {
        self.manager.lock().unwrap().next_event().map(|e| e.into())
    }

    pub fn list_contacts(&self) -> Vec<ContactInfo> {
        self.manager.lock().unwrap().list_contacts()
    }

    /// Create an unencrypted envelope wrapping an onion packet (for Swift)
    pub fn create_onion_envelope(&self, packet_bytes: Vec<u8>) -> Vec<u8> {
        use crate::messaging::protocol::{Message, MessageEnvelope};
        let manager = self.manager.lock().unwrap();
        let my_peer_id = manager.peer_id();
        let onion_msg = Message::onion_packet(&packet_bytes);
        let envelope = MessageEnvelope::unencrypted(my_peer_id, &onion_msg);
        envelope.to_bytes()
    }
}

pub fn create_messaging_manager(peer_id: String) -> Arc<MessagingAPI> {
    Arc::new(MessagingAPI::new(peer_id))
}
