//! Signal Protocol implementation for SecureChat
//!
//! Provides:
//! - X3DH (Extended Triple Diffie-Hellman) key exchange
//! - Double Ratchet for message encryption
//! - Session management

pub mod keys;
pub mod x3dh;
pub mod ratchet;
pub mod session;

pub use keys::{IdentityKeyPair, PreKeyBundle, SignedPreKey, OneTimePreKey};
pub use x3dh::{X3DHSession, X3DHError};
pub use ratchet::{DoubleRatchet, RatchetError};
pub use session::{Session, SessionError, EncryptedMessage};

#[cfg(test)]
mod tests;
