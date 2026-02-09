//! Network module for P2P communication using libp2p
//!
//! Provides:
//! - Peer discovery (Kademlia DHT + mDNS)
//! - NAT traversal (dcutr/relay)
//! - Encrypted transport (Noise protocol)

mod node;
mod behaviour;
mod config;
mod persistence;
pub mod api;
pub mod chat;
pub mod relay_node;

pub use node::{P2PNode, NodeEvent, PeerInfo};
pub use config::NetworkConfig;
pub use api::{NetworkManager, NetworkError, NetworkEvent, create_network_manager};

#[cfg(test)]
mod tests;
