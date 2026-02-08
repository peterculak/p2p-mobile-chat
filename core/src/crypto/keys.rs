//! Cryptographic key types for Signal Protocol
//!
//! Provides identity keys, signed prekeys, and one-time prekeys.

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

/// Identity key pair (Ed25519 for signing, X25519 for key exchange)
#[derive(Clone)]
pub struct IdentityKeyPair {
    /// Ed25519 signing key
    signing_key: SigningKey,
    /// X25519 private key (derived from signing key)
    x25519_private: StaticSecret,
    /// X25519 public key
    x25519_public: X25519PublicKey,
}

impl IdentityKeyPair {
    /// Generate a new identity key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        
        // Derive X25519 key from Ed25519 private key bytes
        let private_bytes = signing_key.to_bytes();
        let x25519_private = StaticSecret::from(private_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_private);
        
        Self {
            signing_key,
            x25519_private,
            x25519_public,
        }
    }

    /// Get the Ed25519 public key for verification
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the X25519 public key for key exchange
    pub fn public_key(&self) -> X25519PublicKey {
        self.x25519_public
    }

    /// Get the X25519 private key (for internal use)
    pub(crate) fn private_key(&self) -> &StaticSecret {
        &self.x25519_private
    }

    /// Sign data with Ed25519
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    /// Get public key as bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.x25519_public.to_bytes()
    }

    /// Serialize to bytes (for storage)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.signing_key.to_bytes());
        bytes[32..].copy_from_slice(&self.x25519_private.to_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, KeyError> {
        let signing_bytes: [u8; 32] = bytes[..32].try_into().map_err(|_| KeyError::InvalidFormat)?;
        let signing_key = SigningKey::from_bytes(&signing_bytes);
        
        let private_bytes: [u8; 32] = bytes[32..].try_into().map_err(|_| KeyError::InvalidFormat)?;
        let x25519_private = StaticSecret::from(private_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_private);
        
        Ok(Self {
            signing_key,
            x25519_private,
            x25519_public,
        })
    }
}

/// Signed prekey (medium-term, signed by identity key)
#[derive(Clone)]
pub struct SignedPreKey {
    /// Key ID
    pub id: u32,
    /// X25519 key pair
    private_key: StaticSecret,
    public_key: X25519PublicKey,
    /// Signature from identity key
    signature: Signature,
}

impl SignedPreKey {
    /// Generate a new signed prekey
    pub fn generate(id: u32, identity: &IdentityKeyPair) -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        
        // Sign the public key with identity
        let signature = identity.sign(public_key.as_bytes());
        
        Self {
            id,
            private_key,
            public_key,
            signature,
        }
    }

    pub fn public_key(&self) -> X25519PublicKey {
        self.public_key
    }

    pub fn signature(&self) -> Signature {
        self.signature
    }

    pub(crate) fn private_key(&self) -> &StaticSecret {
        &self.private_key
    }

    /// Verify signature against identity public key
    pub fn verify(&self, identity_public: &VerifyingKey) -> bool {
        identity_public.verify(self.public_key.as_bytes(), &self.signature).is_ok()
    }
}

/// One-time prekey (ephemeral, used once)
#[derive(Clone)]
pub struct OneTimePreKey {
    /// Key ID
    pub id: u32,
    /// X25519 key pair
    private_key: StaticSecret,
    public_key: X25519PublicKey,
}

impl OneTimePreKey {
    /// Generate a new one-time prekey
    pub fn generate(id: u32) -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        
        Self {
            id,
            private_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> X25519PublicKey {
        self.public_key
    }

    pub(crate) fn private_key(&self) -> &StaticSecret {
        &self.private_key
    }
}

/// Bundle of public keys shared with peers
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Identity public key (X25519)
    pub identity_key: X25519PublicKey,
    /// Identity verifying key (Ed25519)
    pub identity_verifying_key: VerifyingKey,
    /// Signed prekey
    pub signed_prekey: X25519PublicKey,
    pub signed_prekey_id: u32,
    pub signed_prekey_signature: Signature,
    /// Optional one-time prekey
    pub one_time_prekey: Option<(u32, X25519PublicKey)>,
}

impl PreKeyBundle {
    /// Create a bundle from our keys
    pub fn new(
        identity: &IdentityKeyPair,
        signed_prekey: &SignedPreKey,
        one_time_prekey: Option<&OneTimePreKey>,
    ) -> Self {
        Self {
            identity_key: identity.public_key(),
            identity_verifying_key: identity.verifying_key(),
            signed_prekey: signed_prekey.public_key(),
            signed_prekey_id: signed_prekey.id,
            signed_prekey_signature: signed_prekey.signature(),
            one_time_prekey: one_time_prekey.map(|k| (k.id, k.public_key())),
        }
    }

    /// Verify the signed prekey signature
    pub fn verify(&self) -> bool {
        self.identity_verifying_key
            .verify(self.signed_prekey.as_bytes(), &self.signed_prekey_signature)
            .is_ok()
    }
}

/// Key-related errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum KeyError {
    #[error("Invalid key format")]
    InvalidFormat,
    #[error("Signature verification failed")]
    SignatureInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_key_generation() {
        let identity = IdentityKeyPair::generate();
        assert_eq!(identity.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_identity_key_serialization() {
        let identity = IdentityKeyPair::generate();
        let bytes = identity.to_bytes();
        let restored = IdentityKeyPair::from_bytes(&bytes).unwrap();
        assert_eq!(identity.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_signed_prekey_generation() {
        let identity = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKey::generate(1, &identity);
        
        // Verify signature
        assert!(signed_prekey.verify(&identity.verifying_key()));
    }

    #[test]
    fn test_one_time_prekey_generation() {
        let otpk = OneTimePreKey::generate(1);
        assert_eq!(otpk.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_prekey_bundle() {
        let identity = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKey::generate(1, &identity);
        let one_time_prekey = OneTimePreKey::generate(1);
        
        let bundle = PreKeyBundle::new(&identity, &signed_prekey, Some(&one_time_prekey));
        
        // Bundle should verify
        assert!(bundle.verify());
    }

    #[test]
    fn test_identity_signing() {
        let identity = IdentityKeyPair::generate();
        let data = b"test message";
        let signature = identity.sign(data);
        
        // Verify with public key
        assert!(identity.verifying_key().verify(data, &signature).is_ok());
    }
}
