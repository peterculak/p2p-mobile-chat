//! Messaging module for P2P encrypted communications
//!
//! Combines the network layer with crypto to enable secure messaging.

mod protocol;
mod handler;
mod contact;
pub mod manager;

pub use protocol::{Message, MessageType, MessageEnvelope, ProtocolError};
pub use handler::MessageHandler;
pub use contact::{Contact, ContactStore};
pub use manager::{MessagingManager, MessagingError, MessagingEvent, ContactInfo};

#[cfg(test)]
mod tests;
