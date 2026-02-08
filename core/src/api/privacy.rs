use crate::privacy::manager::{PrivacyManager, PrivacyConfig, PrivacyEvent as InternalEvent};
use std::sync::{Arc, Mutex};

/// Privacy manager exposed to FFI
pub struct PrivacyAPI {
    manager: Arc<Mutex<PrivacyManager>>,
}

#[derive(Debug, Clone)]
pub enum PrivacyAPIEvent {
    RelayPacket {
        next_peer_id: String,
        packet_bytes: Vec<u8>,
        delay_ms: u64,
    },
    PacketDelivered {
        payload: Vec<u8>,
    },
    DeliverPayload {
        next_peer_id: String,
        payload: Vec<u8>,
    },
    CircuitBuilt {
        circuit_id: u64,
        hops: u64,
    },
    Error {
        message: String,
    },
}

impl From<InternalEvent> for PrivacyAPIEvent {
    fn from(e: InternalEvent) -> Self {
        match e {
            InternalEvent::RelayPacket { next_peer_id, packet_bytes, delay_ms } => {
                PrivacyAPIEvent::RelayPacket { next_peer_id, packet_bytes, delay_ms }
            },
            InternalEvent::PacketDelivered { payload } => {
                PrivacyAPIEvent::PacketDelivered { payload }
            },
            InternalEvent::CircuitBuilt { circuit_id, hops } => {
                PrivacyAPIEvent::CircuitBuilt { circuit_id, hops: hops as u64 }
            },
            InternalEvent::DeliverPayload { next_peer_id, payload } => {
                PrivacyAPIEvent::DeliverPayload { next_peer_id, payload }
            },
            InternalEvent::Error { message } => {
                PrivacyAPIEvent::Error { message }
            },
        }
    }
}

impl PrivacyAPI {
    pub fn new() -> Self {
        let config = PrivacyConfig::default();
        Self {
            manager: Arc::new(Mutex::new(PrivacyManager::new(config))),
        }
    }

    pub fn set_onion_enabled(&self, enabled: bool) {
        self.manager.lock().unwrap().set_onion_enabled(enabled);
    }

    pub fn is_onion_enabled(&self) -> bool {
        self.manager.lock().unwrap().is_onion_enabled()
    }

    pub fn register_relay(&self, peer_id: String, public_key_hex: String) {
        if let Ok(key_bytes) = hex::decode(public_key_hex) {
            if key_bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                self.manager.lock().unwrap().register_relay(&peer_id, key);
            }
        }
    }

    pub fn unregister_relay(&self, peer_id: String) {
        self.manager.lock().unwrap().unregister_relay(&peer_id);
    }

    pub fn relay_count(&self) -> u64 {
        self.manager.lock().unwrap().relay_count() as u64
    }

    pub fn can_build_circuit(&self) -> bool {
        self.manager.lock().unwrap().can_build_circuit()
    }

    pub fn relay_public_key(&self) -> String {
        hex::encode(self.manager.lock().unwrap().relay_public_key())
    }

    pub fn process_incoming(&self, packet_bytes: Vec<u8>) -> bool {
        self.manager.lock().unwrap().process_incoming(&packet_bytes)
    }

    pub fn next_event(&self) -> Option<PrivacyAPIEvent> {
        self.manager.lock().unwrap().next_event().map(|e| e.into())
    }
    
    // Helper to wrap a message - returns tuple of (entry_peer_id, packet_bytes, delay_ms)
    // Returns None if failed or disabled
    pub fn wrap_message(&self, payload: Vec<u8>, destination_peer_id: String) -> Option<OutgoingOnionPacket> {
        self.manager.lock().unwrap().wrap_message(&payload, &destination_peer_id)
            .map(|onion| OutgoingOnionPacket {
                entry_peer_id: onion.entry_peer_id,
                packet_bytes: onion.packet_bytes,
                delay_ms: onion.delay_ms,
            })
    }
}

#[derive(Debug, Clone)]
pub struct OutgoingOnionPacket {
    pub entry_peer_id: String,
    pub packet_bytes: Vec<u8>,
    pub delay_ms: u64,
}

pub fn create_privacy_manager() -> Arc<PrivacyAPI> {
    Arc::new(PrivacyAPI::new())
}
