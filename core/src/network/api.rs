//! Network API exposed via UniFFI for iOS/Android
//!
//! This module provides a synchronous wrapper around the async P2P node
//! that can be called from Swift/Kotlin via UniFFI.

use crate::network::{P2PNode, NetworkConfig, NodeEvent, PeerInfo as InternalPeerInfo};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;



/// Network errors exposed to FFI
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Node is already running")]
    AlreadyRunning,
    #[error("Node is not running")]
    NotRunning,
    #[error("Node start failed")]
    StartFailed,
    #[error("Connection failed")]
    ConnectionFailed,
    #[error("Generic error")]
    GenericError,
}

/// Peer information exposed to FFI
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: String,
    pub addresses: Vec<String>,
}

impl From<InternalPeerInfo> for PeerInfo {
    fn from(p: InternalPeerInfo) -> Self {
        Self {
            peer_id: p.peer_id,
            addresses: p.addresses,
        }
    }
}

/// Network events exposed to FFI
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    Listening { address: String },
    PeerDiscovered { peer: PeerInfo },
    PeerDisconnected { peer_id: String },
    MessageReceived { peer_id: String, data: Vec<u8> },
    Error { message: String },
}

impl From<NodeEvent> for NetworkEvent {
    fn from(e: NodeEvent) -> Self {
        match e {
            NodeEvent::Listening { address } => NetworkEvent::Listening { address },
            NodeEvent::PeerDiscovered { peer } => NetworkEvent::PeerDiscovered { 
                peer: peer.into() 
            },
            NodeEvent::PeerDisconnected { peer_id } => NetworkEvent::PeerDisconnected { peer_id },
            NodeEvent::MessageReceived { peer_id, envelope } => {
                let data = envelope.to_bytes();
                NetworkEvent::MessageReceived { peer_id, data }
            },
            NodeEvent::Error { message } => NetworkEvent::Error { message }, // Kept original as requested change was type-incorrect
        }
    }
}

impl From<String> for NetworkError {
    fn from(_s: String) -> Self {
        NetworkError::GenericError
    }
}

/// Network manager for P2P operations (exposed to FFI)
pub struct NetworkManager {
    /// Tokio runtime for async operations
    runtime: Runtime,
    /// The P2P node
    node: Arc<Mutex<P2PNode>>,
    /// Event receiver
    event_rx: Arc<Mutex<Option<mpsc::Receiver<NodeEvent>>>>,
    /// Our peer ID
    peer_id: String,
    /// Running state
    is_running: Arc<Mutex<bool>>,
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new() -> Self {
        let runtime = Runtime::new().expect("Failed to create Tokio runtime");
        let config = NetworkConfig::local_only();
        let node = P2PNode::new(config);
        let peer_id = node.peer_id().to_string();
        
        Self {
            runtime,
            node: Arc::new(Mutex::new(node)),
            event_rx: Arc::new(Mutex::new(None)),
            peer_id,
            is_running: Arc::new(Mutex::new(false)),
        }
    }

    /// Get our peer ID
    pub fn get_peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// Start the P2P node
    pub fn start(&self) -> Result<(), NetworkError> {
        let mut running = self.is_running.lock().unwrap();
        if *running {
            return Err(NetworkError::AlreadyRunning);
        }

        let config = NetworkConfig::local_only();
        let mut node = self.node.lock().unwrap();
        
        self.runtime.block_on(async {
            node.start(config).await
        }).map_err(|_| NetworkError::StartFailed)?;

        *running = true;
        Ok(())
    }

    /// Stop the P2P node
    pub fn stop(&self) {
        let mut running = self.is_running.lock().unwrap();
        if !*running {
            return;
        }

        let mut node = self.node.lock().unwrap();
        self.runtime.block_on(async {
            let _ = node.stop().await;
        });
        
        *running = false;
    }

    /// Check if the node is running
    pub fn is_running(&self) -> bool {
        *self.is_running.lock().unwrap()
    }

    /// Get connected peers
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        let node = self.node.lock().unwrap();
        self.runtime.block_on(async {
            node.get_peers().await.into_iter().map(|p| p.into()).collect()
        })
    }

    /// Poll for the next event (non-blocking)
    pub fn poll_event(&self) -> Option<NetworkEvent> {
        let mut node = self.node.lock().unwrap();
        
        // Try to receive without blocking
        self.runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                node.next_event()
            ).await.ok().flatten().map(|e| e.into())
        })
    }

    /// Send a message to a peer
    pub fn send_message(&self, peer_id: String, data: Vec<u8>) -> Result<(), NetworkError> {
        // Deserialize envelope
        let envelope = crate::messaging::MessageEnvelope::from_bytes(&data)
            .map_err(|_| NetworkError::GenericError)?;
            
        let mut node = self.node.lock().unwrap();
        
        self.runtime.block_on(async {
            node.send_message(peer_id, envelope).await
        }).map_err(|_| NetworkError::ConnectionFailed)
    }
}

/// Create a new network manager (FFI entry point)
pub fn create_network_manager() -> Arc<NetworkManager> {
    Arc::new(NetworkManager::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_manager_creation() {
        let manager = create_network_manager();
        assert!(!manager.get_peer_id().is_empty());
        assert!(!manager.is_running());
    }

    #[test]
    fn test_network_manager_start_stop() {
        let manager = create_network_manager();
        
        // Start
        manager.start().expect("Failed to start");
        assert!(manager.is_running());
        
        // Double start should fail
        assert!(manager.start().is_err());
        
        // Stop
        manager.stop();
        assert!(!manager.is_running());
    }

    #[test]
    fn test_network_manager_get_peers() {
        let manager = create_network_manager();
        manager.start().expect("Failed to start");
        
        // Initially no peers
        let peers = manager.get_peers();
        assert!(peers.is_empty());
        
        manager.stop();
    }
}
