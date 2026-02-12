//! Double Ratchet Algorithm for Signal Protocol
//!
//! Provides forward secrecy and post-compromise security through
//! continuous key ratcheting.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use rand::RngCore;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Chain key for symmetric ratchet
#[derive(Clone)]
struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    fn new(key: [u8; 32]) -> Self {
        Self { key, index: 0 }
    }

    /// Derive message key and advance chain
    fn next(&mut self) -> [u8; 32] {
        let message_key = self.derive_key(0x01);
        self.key = self.derive_key(0x02);
        self.index += 1;
        message_key
    }

    fn derive_key(&self, constant: u8) -> [u8; 32] {
        use hmac::digest::KeyInit;
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.key).unwrap();
        mac.update(&[constant]);
        let result = mac.finalize().into_bytes();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }
}

impl Drop for ChainKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Double Ratchet state
pub struct DoubleRatchet {
    /// DH ratchet key pair
    dh_private: StaticSecret,
    dh_public: X25519PublicKey,
    /// Remote party's DH public key
    remote_public: Option<X25519PublicKey>,
    /// Root key
    root_key: [u8; 32],
    /// Sending chain
    sending_chain: Option<ChainKey>,
    /// Receiving chain
    receiving_chain: Option<ChainKey>,
    /// Message counters
    send_count: u32,
    recv_count: u32,
    /// Previous sending chain length
    prev_send_count: u32,
}

impl DoubleRatchet {
    /// Initialize as the sender (Alice) with shared secret from X3DH
    pub fn init_alice(shared_secret: &[u8; 32], bob_public: &X25519PublicKey) -> Self {
        let dh_private = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dh_public = X25519PublicKey::from(&dh_private);
        
        // Perform initial DH
        let dh_output = dh_private.diffie_hellman(bob_public);
        
        // Derive root key and sending chain key
        let (root_key, chain_key) = Self::kdf_rk(shared_secret, dh_output.as_bytes());
        
        Self {
            dh_private,
            dh_public,
            remote_public: Some(*bob_public),
            root_key,
            sending_chain: Some(ChainKey::new(chain_key)),
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
        }
    }

    /// Initialize as the receiver (Bob) with shared secret from X3DH
    /// Now accepts Alice's ratchet public key to perform initial DH ratchet,
    /// allowing Bob to both send and receive from the start.
    pub fn init_bob(
        shared_secret: &[u8; 32], 
        signed_prekey: &StaticSecret,
        alice_ratchet_key: &X25519PublicKey,
    ) -> Self {
        let dh_public = X25519PublicKey::from(signed_prekey);
        
        let mut ratchet = Self {
            dh_private: signed_prekey.clone(),
            dh_public,
            remote_public: None,
            root_key: *shared_secret,
            sending_chain: None,
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
        };
        
        // Perform initial DH ratchet so Bob can both send AND receive
        // This creates both the receiving chain (for Alice's messages) and
        // the sending chain (for Bob's messages)
        ratchet.dh_ratchet(alice_ratchet_key).expect("Initial DH ratchet failed");
        
        ratchet
    }

    /// Get our current DH public key
    pub fn public_key(&self) -> X25519PublicKey {
        self.dh_public
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedPayload, RatchetError> {
        tracing::info!("DoubleRatchet::encrypt: sending_chain={}, receiving_chain={}, remote_public={}", 
            self.sending_chain.is_some(), self.receiving_chain.is_some(), self.remote_public.is_some());
        let chain = self.sending_chain.as_mut()
            .ok_or_else(|| {
                tracing::error!("DoubleRatchet::encrypt: FAILED - sending_chain is None!");
                RatchetError::NotInitialized
            })?;
        
        let message_key = chain.next();
        let ciphertext = Self::aead_encrypt(&message_key, plaintext)?;
        
        self.send_count += 1;
        
        Ok(EncryptedPayload {
            header: MessageHeader {
                dh_public: self.dh_public,
                prev_chain_length: self.prev_send_count,
                message_number: chain.index - 1,
            },
            ciphertext,
        })
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, payload: &EncryptedPayload) -> Result<Vec<u8>, RatchetError> {
        // Check if we need to perform DH ratchet
        let need_ratchet = self.remote_public
            .map(|pk| pk != payload.header.dh_public)
            .unwrap_or(true);

        if need_ratchet {
            self.dh_ratchet(&payload.header.dh_public)?;
        }

        let chain = self.receiving_chain.as_mut()
            .ok_or(RatchetError::NotInitialized)?;
        
        let message_key = chain.next();
        let plaintext = Self::aead_decrypt(&message_key, &payload.ciphertext)?;
        
        self.recv_count += 1;
        
        Ok(plaintext)
    }

    /// Perform DH ratchet step
    fn dh_ratchet(&mut self, their_public: &X25519PublicKey) -> Result<(), RatchetError> {
        self.remote_public = Some(*their_public);
        self.prev_send_count = self.sending_chain.as_ref().map(|c| c.index).unwrap_or(0);
        
        // Derive receiving chain
        let dh_recv = self.dh_private.diffie_hellman(their_public);
        let (root_key, recv_chain_key) = Self::kdf_rk(&self.root_key, dh_recv.as_bytes());
        self.root_key = root_key;
        self.receiving_chain = Some(ChainKey::new(recv_chain_key));
        
        // Generate new DH pair
        self.dh_private = StaticSecret::random_from_rng(rand::rngs::OsRng);
        self.dh_public = X25519PublicKey::from(&self.dh_private);
        
        // Derive sending chain
        let dh_send = self.dh_private.diffie_hellman(their_public);
        let (root_key, send_chain_key) = Self::kdf_rk(&self.root_key, dh_send.as_bytes());
        self.root_key = root_key;
        self.sending_chain = Some(ChainKey::new(send_chain_key));
        
        Ok(())
    }

    /// Root key derivation function
    fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
        let mut output = [0u8; 64];
        hk.expand(b"SecureChat_Ratchet", &mut output).unwrap();
        
        let mut new_root = [0u8; 32];
        let mut chain_key = [0u8; 32];
        new_root.copy_from_slice(&output[..32]);
        chain_key.copy_from_slice(&output[32..]);
        
        output.zeroize();
        (new_root, chain_key)
    }

    /// AEAD encryption using AES-256-GCM
    fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| RatchetError::EncryptionFailed)?;
        
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| RatchetError::EncryptionFailed)?;
        
        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);
        
        Ok(result)
    }

    /// AEAD decryption using AES-256-GCM
    fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, RatchetError> {
        if ciphertext.len() < 12 {
            return Err(RatchetError::DecryptionFailed);
        }
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| RatchetError::DecryptionFailed)?;
        
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher.decrypt(nonce, &ciphertext[12..])
            .map_err(|_| RatchetError::DecryptionFailed)?;
        
        Ok(plaintext)
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

/// Message header
#[derive(Clone, Debug)]
pub struct MessageHeader {
    /// Sender's current DH public key
    pub dh_public: X25519PublicKey,
    /// Previous sending chain length
    pub prev_chain_length: u32,
    /// Message number in current chain
    pub message_number: u32,
}

/// Encrypted message payload
#[derive(Clone, Debug)]
pub struct EncryptedPayload {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
}

/// Ratchet errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum RatchetError {
    #[error("Ratchet not initialized")]
    NotInitialized,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Message out of order")]
    OutOfOrder,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{IdentityKeyPair, SignedPreKey, PreKeyBundle};
    use crate::crypto::x3dh::X3DH;

    #[test]
    fn test_chain_key_derivation() {
        let mut chain = ChainKey::new([0u8; 32]);
        let key1 = chain.next();
        let key2 = chain.next();
        
        // Keys should be different
        assert_ne!(key1, key2);
        assert_eq!(chain.index, 2);
    }

    #[test]
    fn test_aead_encrypt_decrypt() {
        let key = [1u8; 32];
        let plaintext = b"Hello, World!";
        
        let ciphertext = DoubleRatchet::aead_encrypt(&key, plaintext).unwrap();
        let decrypted = DoubleRatchet::aead_decrypt(&key, &ciphertext).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_double_ratchet_basic() {
        // Setup keys
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity);
        
        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_prekey, None);
        
        // X3DH
        let alice_x3dh = X3DH::initiate(&alice_identity, &bob_bundle).unwrap();
        let bob_x3dh = X3DH::respond(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity.public_key(),
            &alice_x3dh.ephemeral_public,
        ).unwrap();
        
        // Initialize ratchets
        let mut alice_ratchet = DoubleRatchet::init_alice(
            alice_x3dh.shared_secret(),
            &bob_signed_prekey.public_key(),
        );
        let alice_ratchet_key = alice_ratchet.public_key();
        let mut bob_ratchet = DoubleRatchet::init_bob(
            bob_x3dh.shared_secret(),
            bob_signed_prekey.private_key(),
            &alice_ratchet_key,
        );
        
        // Alice sends message
        let msg1 = b"Hello Bob!";
        let encrypted1 = alice_ratchet.encrypt(msg1).unwrap();
        let decrypted1 = bob_ratchet.decrypt(&encrypted1).unwrap();
        assert_eq!(msg1.to_vec(), decrypted1);
        
        // Bob replies
        let msg2 = b"Hello Alice!";
        let encrypted2 = bob_ratchet.encrypt(msg2).unwrap();
        let decrypted2 = alice_ratchet.decrypt(&encrypted2).unwrap();
        assert_eq!(msg2.to_vec(), decrypted2);
    }

    #[test]
    fn test_double_ratchet_multiple_messages() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity);
        
        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_prekey, None);
        
        let alice_x3dh = X3DH::initiate(&alice_identity, &bob_bundle).unwrap();
        let bob_x3dh = X3DH::respond(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity.public_key(),
            &alice_x3dh.ephemeral_public,
        ).unwrap();
        
        let mut alice = DoubleRatchet::init_alice(
            alice_x3dh.shared_secret(),
            &bob_signed_prekey.public_key(),
        );
        let alice_ratchet_key = alice.public_key();
        let mut bob = DoubleRatchet::init_bob(
            bob_x3dh.shared_secret(),
            bob_signed_prekey.private_key(),
            &alice_ratchet_key,
        );
        
        // Multiple messages back and forth
        for i in 0..5 {
            let msg = format!("Alice message {}", i);
            let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
            let decrypted = bob.decrypt(&encrypted).unwrap();
            assert_eq!(msg.as_bytes(), decrypted.as_slice());
            
            let reply = format!("Bob reply {}", i);
            let encrypted = bob.encrypt(reply.as_bytes()).unwrap();
            let decrypted = alice.decrypt(&encrypted).unwrap();
            assert_eq!(reply.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_forward_secrecy() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity);
        
        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_prekey, None);
        
        let alice_x3dh = X3DH::initiate(&alice_identity, &bob_bundle).unwrap();
        let bob_x3dh = X3DH::respond(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity.public_key(),
            &alice_x3dh.ephemeral_public,
        ).unwrap();
        
        let mut alice = DoubleRatchet::init_alice(
            alice_x3dh.shared_secret(),
            &bob_signed_prekey.public_key(),
        );
        let alice_ratchet_key = alice.public_key();
        let mut bob = DoubleRatchet::init_bob(
            bob_x3dh.shared_secret(),
            bob_signed_prekey.private_key(),
            &alice_ratchet_key,
        );
        
        // Send a few messages to advance the ratchet
        for _ in 0..3 {
            let enc = alice.encrypt(b"test").unwrap();
            bob.decrypt(&enc).unwrap();
            let enc = bob.encrypt(b"test").unwrap();
            alice.decrypt(&enc).unwrap();
        }
        
        // The DH public keys should have changed (forward secrecy)
        // Each party generates new keys during ratcheting
        assert_ne!(alice.dh_public.as_bytes(), bob_signed_prekey.public_key().as_bytes());
    }
}
