//! Contact management for storing peer information
//!
//! Manages contacts and their associated crypto sessions.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

use crate::crypto::keys::{IdentityKeyPair, SignedPreKey, OneTimePreKey, PreKeyBundle};
use crate::crypto::session::{Session, InitialMessage, SessionError};

/// A contact (peer we can message)
#[derive(Clone)]
pub struct Contact {
    /// Peer ID (libp2p)
    pub peer_id: String,
    /// Display name
    pub name: String,
    /// Their identity public key
    pub identity_key: [u8; 32],
    /// When we first connected
    pub created_at: u64,
    /// Last message timestamp
    pub last_message_at: Option<u64>,
    /// Is session established?
    pub session_established: bool,
}

impl Contact {
    pub fn new(peer_id: &str, name: &str, identity_key: [u8; 32]) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            name: name.to_string(),
            identity_key,
            created_at: now_ms(),
            last_message_at: None,
            session_established: false,
        }
    }

    /// Serialize for storage
    pub fn to_json(&self) -> String {
        serde_json::to_string(&ContactData {
            peer_id: self.peer_id.clone(),
            name: self.name.clone(),
            identity_key: hex::encode(self.identity_key),
            created_at: self.created_at,
            last_message_at: self.last_message_at,
        }).unwrap_or_default()
    }
}

#[derive(Serialize, Deserialize)]
struct ContactData {
    peer_id: String,
    name: String,
    identity_key: String,
    created_at: u64,
    last_message_at: Option<u64>,
}

/// Store for contacts and their sessions
pub struct ContactStore {
    /// Our identity
    our_identity: IdentityKeyPair,
    /// Our current signed prekey
    signed_prekey: SignedPreKey,
    /// Available one-time prekeys
    one_time_prekeys: Vec<OneTimePreKey>,
    /// Next one-time prekey ID
    next_otpk_id: u32,
    /// Contacts by peer ID
    contacts: HashMap<String, Contact>,
    /// Active sessions by peer ID
    sessions: HashMap<String, Session>,
}

impl ContactStore {
    /// Create a new contact store with fresh identity
    pub fn new() -> Self {
        let identity = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKey::generate(1, &identity);
        
        // Generate initial batch of one-time prekeys
        let one_time_prekeys: Vec<_> = (1..=10)
            .map(|id| OneTimePreKey::generate(id))
            .collect();

        Self {
            our_identity: identity,
            signed_prekey,
            one_time_prekeys,
            next_otpk_id: 11,
            contacts: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    /// Get our identity key pair
    pub fn identity(&self) -> &IdentityKeyPair {
        &self.our_identity
    }

    /// Get our prekey bundle for sharing
    pub fn get_prekey_bundle(&mut self) -> PreKeyBundle {
        // Just take the first one without removing it (for simplicity in this P2P serverless model)
        // In a real server setup, the server would hold these and hand them out.
        // Here we just use the first available one as "current"
        let otpk = self.one_time_prekeys.first().cloned();
        
        // Replenish if running low
        if self.one_time_prekeys.len() < 5 {
            for _ in 0..5 {
                self.one_time_prekeys.push(OneTimePreKey::generate(self.next_otpk_id));
                self.next_otpk_id += 1;
            }
        }

        PreKeyBundle::new(&self.our_identity, &self.signed_prekey, otpk.as_ref())
    }

    /// Add or update a contact
    pub fn add_contact(&mut self, contact: Contact) {
        self.contacts.insert(contact.peer_id.clone(), contact);
    }

    /// Get a contact by peer ID
    pub fn get_contact(&self, peer_id: &str) -> Option<&Contact> {
        self.contacts.get(peer_id)
    }

    /// Get mutable contact
    pub fn get_contact_mut(&mut self, peer_id: &str) -> Option<&mut Contact> {
        self.contacts.get_mut(peer_id)
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Vec<&Contact> {
        self.contacts.values().collect()
    }

    /// Initiate a session with a contact using their prekey bundle
    pub fn initiate_session(
        &mut self, 
        peer_id: &str, 
        their_bundle: &PreKeyBundle
    ) -> Result<InitialMessage, SessionError> {
        let (session, initial_msg) = Session::initiate(
            self.our_identity.clone(),
            their_bundle,
        )?;
        
        self.sessions.insert(peer_id.to_string(), session);
        
        if let Some(contact) = self.contacts.get_mut(peer_id) {
            contact.session_established = true;
        }
        
        Ok(initial_msg)
    }

    /// Accept a session from a peer
    pub fn accept_session(
        &mut self,
        peer_id: &str,
        initial_msg: &InitialMessage,
        used_otpk_id: Option<u32>,
    ) -> Result<(), SessionError> {
        // Find the used one-time prekey if specified
        let otpk = used_otpk_id.and_then(|id| {
            // Find key with matching ID
            self.one_time_prekeys.iter().find(|k| k.id == id).cloned()
        });

        let session = Session::respond(
            self.our_identity.clone(),
            &self.signed_prekey,
            otpk.as_ref(),
            initial_msg,
        )?;
        
        // Remove the used one-time prekey if found
        if let Some(id) = used_otpk_id {
            self.one_time_prekeys.retain(|k| k.id != id);
        }
        
        self.sessions.insert(peer_id.to_string(), session);
        
        if let Some(contact) = self.contacts.get_mut(peer_id) {
            contact.session_established = true;
        }
        
        Ok(())
    }

    /// Get a session for encrypting/decrypting
    pub fn get_session(&mut self, peer_id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(peer_id)
    }

    /// Check if we have a session with a peer
    pub fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.contains_key(peer_id)
    }

    /// Remove a contact and session
    pub fn remove_contact(&mut self, peer_id: &str) {
        self.contacts.remove(peer_id);
        self.sessions.remove(peer_id);
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

    #[test]
    fn test_contact_creation() {
        let contact = Contact::new("peer123", "Alice", [1u8; 32]);
        assert_eq!(contact.peer_id, "peer123");
        assert_eq!(contact.name, "Alice");
        assert!(!contact.session_established);
    }

    #[test]
    fn test_contact_store_creation() {
        let store = ContactStore::new();
        assert!(store.list_contacts().is_empty());
        assert_eq!(store.one_time_prekeys.len(), 10);
    }

    #[test]
    fn test_add_and_get_contact() {
        let mut store = ContactStore::new();
        let contact = Contact::new("peer123", "Bob", [2u8; 32]);
        store.add_contact(contact);
        
        let retrieved = store.get_contact("peer123").unwrap();
        assert_eq!(retrieved.name, "Bob");
    }

    #[test]
    fn test_prekey_bundle_generation() {
        let mut store = ContactStore::new();
        let bundle = store.get_prekey_bundle();
        
        // Should NOT have consumed one OTPk yet (it's consumed on session accept)
        assert_eq!(store.one_time_prekeys.len(), 10);
        
        // Bundle should verify
        assert!(bundle.verify());
    }

    #[test]
    fn test_session_establishment() {
        // Alice's store
        let mut alice_store = ContactStore::new();
        let alice_contact = Contact::new("alice_peer", "Alice", 
            alice_store.identity().public_key_bytes());
        
        // Bob's store
        let mut bob_store = ContactStore::new();
        let bob_contact = Contact::new("bob_peer", "Bob",
            bob_store.identity().public_key_bytes());
        
        // Add contacts
        alice_store.add_contact(bob_contact);
        bob_store.add_contact(alice_contact);
        
        // Alice gets Bob's bundle and initiates
        let bob_bundle = bob_store.get_prekey_bundle();
        let initial_msg = alice_store.initiate_session("bob_peer", &bob_bundle).unwrap();
        
        // Bob accepts
        bob_store.accept_session("alice_peer", &initial_msg, initial_msg.used_one_time_prekey_id).unwrap();
        
        // Both should have sessions
        assert!(alice_store.has_session("bob_peer"));
        assert!(bob_store.has_session("alice_peer"));
    }
}
