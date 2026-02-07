//! Signal Protocol implementation for SecureChat
//!
//! Provides:
//! - X3DH (Extended Triple Diffie-Hellman) key exchange
//! - Double Ratchet for message encryption
//! - Session management

mod keys;
mod x3dh;
mod ratchet;
mod session;

pub use keys::{IdentityKeyPair, PreKeyBundle, SignedPreKey, OneTimePreKey};
pub use x3dh::{X3DHSession, X3DHError};
pub use ratchet::{DoubleRatchet, RatchetError};
pub use session::{Session, SessionError, EncryptedMessage};

#[cfg(test)]
mod tests;
