//! Tests for network module

use super::*;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_node_creation() {
    let config = NetworkConfig::default();
    let node = P2PNode::new(config);
    
    // Peer ID should be a valid base58 string
    assert!(!node.peer_id().is_empty());
    assert!(node.peer_id().len() > 40); // Ed25519 peer IDs are ~52 chars
}

#[tokio::test]
async fn test_node_start_stop() {
    let config = NetworkConfig::local_only();
    let mut node = P2PNode::new(config.clone());
    
    // Initially not running
    assert!(!node.is_running().await);
    
    // Start the node
    node.start(config).await.expect("Failed to start node");
    
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(node.is_running().await);
    
    // Stop the node
    node.stop().await.expect("Failed to stop node");
    
    // Give it time to stop
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_node_listening_event() {
    let config = NetworkConfig::local_only();
    let mut node = P2PNode::new(config.clone());
    
    node.start(config).await.expect("Failed to start node");
    
    // Should receive a listening event
    let event = timeout(Duration::from_secs(5), node.next_event())
        .await
        .expect("Timeout waiting for event")
        .expect("No event received");
    
    match event {
        NodeEvent::Listening { address } => {
            assert!(address.contains("/ip4/"));
            assert!(address.contains("/tcp/"));
        }
        _ => panic!("Expected Listening event, got {:?}", event),
    }
    
    node.stop().await.ok();
}

#[tokio::test]
async fn test_two_nodes_discover_each_other() {
    // Create two nodes
    let config1 = NetworkConfig::local_only();
    let config2 = NetworkConfig::local_only();
    
    let mut node1 = P2PNode::new(config1.clone());
    let mut node2 = P2PNode::new(config2.clone());
    
    // Start both nodes
    node1.start(config1).await.expect("Failed to start node1");
    node2.start(config2).await.expect("Failed to start node2");
    
    // Wait for mDNS discovery (can take a few seconds)
    let mut discovered = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        let peers1 = node1.get_peers().await;
        let peers2 = node2.get_peers().await;
        
        if !peers1.is_empty() || !peers2.is_empty() {
            discovered = true;
            break;
        }
    }
    
    // Clean up
    node1.stop().await.ok();
    node2.stop().await.ok();
    
    // mDNS discovery should work on same machine
    assert!(discovered, "Nodes should discover each other via mDNS");
}

#[test]
fn test_network_config_defaults() {
    let config = NetworkConfig::default();
    assert!(config.enable_mdns);
    assert!(config.enable_kad);
    assert_eq!(config.listen_port, 0);
}

#[test]
fn test_peer_info() {
    let peer = PeerInfo {
        peer_id: "12D3KooWExample".to_string(),
        addresses: vec!["/ip4/127.0.0.1/tcp/1234".to_string()],
    };
    
    assert!(!peer.peer_id.is_empty());
    assert_eq!(peer.addresses.len(), 1);
}
