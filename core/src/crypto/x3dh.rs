//! X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol
//!
//! Implements the Signal Protocol X3DH specification for establishing
//! shared secrets between two parties.

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto::keys::{IdentityKeyPair, SignedPreKey, OneTimePreKey, PreKeyBundle};

/// Info string for HKDF
const X3DH_INFO: &[u8] = b"SecureChat_X3DH";

/// X3DH session result
pub struct X3DHSession {
    /// Shared secret (32 bytes)
    shared_secret: [u8; 32],
    /// Associated data for AEAD
    pub associated_data: Vec<u8>,
    /// Ephemeral public key (sent to Bob)
    pub ephemeral_public: X25519PublicKey,
    /// Used one-time prekey ID (if any)
    pub used_one_time_prekey_id: Option<u32>,
}

impl X3DHSession {
    /// Get the shared secret
    pub fn shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }
}

impl Drop for X3DHSession {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

/// X3DH errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum X3DHError {
    #[error("Invalid prekey bundle signature")]
    InvalidSignature,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
}

/// X3DH key agreement (Alice initiates)
pub struct X3DH;

impl X3DH {
    /// Alice initiates X3DH with Bob's prekey bundle
    pub fn initiate(
        alice_identity: &IdentityKeyPair,
        bob_bundle: &PreKeyBundle,
    ) -> Result<X3DHSession, X3DHError> {
        // Verify Bob's signed prekey
        if !bob_bundle.verify() {
            return Err(X3DHError::InvalidSignature);
        }

        // Generate ephemeral key
        let ephemeral_private = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_private);

        // Compute DH values
        // DH1 = DH(IK_A, SPK_B)
        let dh1 = alice_identity.private_key().diffie_hellman(&bob_bundle.signed_prekey);
        
        // DH2 = DH(EK_A, IK_B)
        let dh2 = ephemeral_private.diffie_hellman(&bob_bundle.identity_key);
        
        // DH3 = DH(EK_A, SPK_B)
        let dh3 = ephemeral_private.diffie_hellman(&bob_bundle.signed_prekey);
        
        // DH4 = DH(EK_A, OPK_B) if one-time prekey exists
        let dh4 = bob_bundle.one_time_prekey.as_ref().map(|(_, opk)| {
            ephemeral_private.diffie_hellman(opk)
        });

        // Concatenate DH outputs
        let mut dh_concat = Vec::with_capacity(128);
        dh_concat.extend_from_slice(dh1.as_bytes());
        dh_concat.extend_from_slice(dh2.as_bytes());
        dh_concat.extend_from_slice(dh3.as_bytes());
        if let Some(ref dh4_result) = dh4 {
            dh_concat.extend_from_slice(dh4_result.as_bytes());
        }

        // Derive shared secret using HKDF
        let shared_secret = Self::kdf(&dh_concat)?;
        dh_concat.zeroize();

        // Create associated data (AD = IK_A || IK_B)
        let mut associated_data = Vec::with_capacity(64);
        associated_data.extend_from_slice(alice_identity.public_key().as_bytes());
        associated_data.extend_from_slice(bob_bundle.identity_key.as_bytes());

        Ok(X3DHSession {
            shared_secret,
            associated_data,
            ephemeral_public,
            used_one_time_prekey_id: bob_bundle.one_time_prekey.as_ref().map(|(id, _)| *id),
        })
    }

    /// Bob responds to Alice's X3DH initiation
    pub fn respond(
        bob_identity: &IdentityKeyPair,
        bob_signed_prekey: &SignedPreKey,
        bob_one_time_prekey: Option<&OneTimePreKey>,
        alice_identity_key: &X25519PublicKey,
        alice_ephemeral_key: &X25519PublicKey,
    ) -> Result<X3DHSession, X3DHError> {
        // Compute DH values (same as Alice but with reversed roles)
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = bob_signed_prekey.private_key().diffie_hellman(alice_identity_key);
        
        // DH2 = DH(IK_B, EK_A)
        let dh2 = bob_identity.private_key().diffie_hellman(alice_ephemeral_key);
        
        // DH3 = DH(SPK_B, EK_A)
        let dh3 = bob_signed_prekey.private_key().diffie_hellman(alice_ephemeral_key);
        
        // DH4 = DH(OPK_B, EK_A) if one-time prekey was used
        let dh4 = bob_one_time_prekey.map(|opk| {
            opk.private_key().diffie_hellman(alice_ephemeral_key)
        });

        // Concatenate DH outputs
        let mut dh_concat = Vec::with_capacity(128);
        dh_concat.extend_from_slice(dh1.as_bytes());
        dh_concat.extend_from_slice(dh2.as_bytes());
        dh_concat.extend_from_slice(dh3.as_bytes());
        if let Some(ref dh4_result) = dh4 {
            dh_concat.extend_from_slice(dh4_result.as_bytes());
        }

        // Derive shared secret using HKDF
        let shared_secret = Self::kdf(&dh_concat)?;
        dh_concat.zeroize();

        // Create associated data (AD = IK_A || IK_B)
        let mut associated_data = Vec::with_capacity(64);
        associated_data.extend_from_slice(alice_identity_key.as_bytes());
        associated_data.extend_from_slice(bob_identity.public_key().as_bytes());

        Ok(X3DHSession {
            shared_secret,
            associated_data,
            ephemeral_public: *alice_ephemeral_key, // Return what Alice sent
            used_one_time_prekey_id: bob_one_time_prekey.map(|k| k.id),
        })
    }

    /// Key derivation function using HKDF-SHA256
    fn kdf(input: &[u8]) -> Result<[u8; 32], X3DHError> {
        // F = 0xFF * 32 (all 0xFF bytes prepended per spec)
        let mut ikm = vec![0xFFu8; 32];
        ikm.extend_from_slice(input);

        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut output = [0u8; 32];
        hk.expand(X3DH_INFO, &mut output)
            .map_err(|_| X3DHError::KeyDerivationFailed)?;
        
        ikm.zeroize();
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x3dh_key_agreement() {
        // Alice's keys
        let alice_identity = IdentityKeyPair::generate();

        // Bob's keys
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity);
        let bob_one_time_prekey = OneTimePreKey::generate(1);

        // Bob publishes his prekey bundle
        let bob_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_signed_prekey,
            Some(&bob_one_time_prekey),
        );

        // Alice initiates X3DH
        let alice_session = X3DH::initiate(&alice_identity, &bob_bundle).unwrap();

        // Bob responds
        let bob_session = X3DH::respond(
            &bob_identity,
            &bob_signed_prekey,
            Some(&bob_one_time_prekey),
            &alice_identity.public_key(),
            &alice_session.ephemeral_public,
        ).unwrap();

        // Both should derive the same shared secret
        assert_eq!(alice_session.shared_secret(), bob_session.shared_secret());
    }

    #[test]
    fn test_x3dh_without_one_time_prekey() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity);

        // Bundle without one-time prekey
        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_prekey, None);

        let alice_session = X3DH::initiate(&alice_identity, &bob_bundle).unwrap();
        let bob_session = X3DH::respond(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity.public_key(),
            &alice_session.ephemeral_public,
        ).unwrap();

        assert_eq!(alice_session.shared_secret(), bob_session.shared_secret());
    }

    #[test]
    fn test_x3dh_invalid_signature_fails() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        
        // Create signed prekey with wrong identity
        let wrong_identity = IdentityKeyPair::generate();
        let bob_signed_prekey = SignedPreKey::generate(1, &wrong_identity);

        // Bundle will have mismatched signature
        let mut bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_prekey, None);
        // Manually set wrong signature (already wrong from generation)

        // This should fail verification
        let result = X3DH::initiate(&alice_identity, &bob_bundle);
        assert!(result.is_err());
    }

    #[test]
    fn test_x3dh_associated_data() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity);

        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_prekey, None);
        let alice_session = X3DH::initiate(&alice_identity, &bob_bundle).unwrap();

        // AD should be IK_A || IK_B (64 bytes)
        assert_eq!(alice_session.associated_data.len(), 64);
    }
}
