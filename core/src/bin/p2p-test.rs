//! P2P Test CLI - Run a node and print discovered peers

use securechat_core::network::{P2PNode, NetworkConfig, NodeEvent};
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .init();

    println!("=== P2P Test Node ===\n");

    let config = NetworkConfig::local_only();
    let mut node = P2PNode::new(config.clone());

    println!("Peer ID: {}", node.peer_id());
    println!("\nStarting node...");

    if let Err(e) = node.start(config).await {
        eprintln!("Failed to start: {}", e);
        return;
    }

    println!("Node started! Listening for peers...\n");
    println!("Run another instance to test discovery.\n");
    println!("---");

    // Event loop
    loop {
        tokio::select! {
            event = node.next_event() => {
                match event {
                    Some(NodeEvent::Listening { address }) => {
                        println!("[LISTEN] {}", address);
                    }
                    Some(NodeEvent::PeerDiscovered { peer }) => {
                        println!("[DISCOVERED] Peer: {}", peer.peer_id);
                        for addr in &peer.addresses {
                            println!("           Addr: {}", addr);
                        }
                    }
                    Some(NodeEvent::PeerDisconnected { peer_id }) => {
                        println!("[DISCONNECTED] {}", peer_id);
                    }
                    Some(NodeEvent::Error { message }) => {
                        println!("[ERROR] {}", message);
                    }
                    None => {
                        println!("Event channel closed");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                let peers = node.get_peers().await;
                println!("\n[STATUS] Connected peers: {}", peers.len());
                for p in &peers {
                    println!("  - {}", p.peer_id);
                }
                println!();
            }
        }
    }
}
