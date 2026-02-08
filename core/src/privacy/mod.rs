//! Privacy module for onion routing and traffic obfuscation
//!
//! Provides:
//! - Sphinx-based onion routing (3-hop circuits)
//! - Traffic obfuscation (padding, timing jitter, decoys)
//! - Relay node functionality
//! - High-level privacy manager

pub mod sphinx_wrapper;
pub mod circuit;
pub mod obfuscation;
pub mod relay;
pub mod manager;

// Re-export main types
pub use sphinx_wrapper::{
    create_onion_packet, process_onion_packet, 
    ProcessResult, SphinxError, RelayNode, OnionDestination,
    generate_relay_keypair, PAYLOAD_SIZE, NUM_HOPS,
};
pub use circuit::{Circuit, CircuitBuilder, CircuitError, RelayRegistry};
pub use obfuscation::{
    pad_message, unpad_message, generate_decoy, 
    random_jitter, random_jitter_ms, apply_jitter,
    CoverTrafficConfig, FIXED_PACKET_SIZE,
};
pub use relay::{RelayHandler, RelayEvent, RelayStats, RelayNodeInfo, ForwardPacket, DeliveredPacket};
pub use manager::{PrivacyManager, PrivacyConfig, PrivacyEvent, OnionOutgoing};
