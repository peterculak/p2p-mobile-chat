//! Network module for P2P communication using libp2p
//!
//! Provides:
//! - Peer discovery (Kademlia DHT + mDNS)
//! - NAT traversal (dcutr/relay)
//! - Encrypted transport (Noise protocol)

mod node;
mod behaviour;
mod config;

pub use node::{P2PNode, NodeEvent, PeerInfo};
pub use config::NetworkConfig;

#[cfg(test)]
mod tests;
