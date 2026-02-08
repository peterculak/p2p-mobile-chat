//! P2P Test CLI - Run a node and print discovered peers

use securechat_core::network::{P2PNode, NetworkConfig, NodeEvent};
use securechat_core::messaging::{Message, MessageEnvelope};
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
    
    let stdin = tokio::io::stdin();
    let mut stdin = tokio::io::BufReader::new(stdin);
    let mut line_buf = String::new();

    println!("Peer ID: {}", node.peer_id());
    println!("Identity Key: {}", node.public_key_hex());
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
                    Some(NodeEvent::MessageReceived { peer_id, envelope }) => {
                        if !envelope.encrypted {
                            if let Ok(msg) = Message::from_bytes(&envelope.payload) {
                                println!("[MESSAGE] From: {}: {}", peer_id, msg.content);
                            } else {
                                println!("[MESSAGE] From: {} (Unencrypted raw bytes: {})", peer_id, envelope.payload.len());
                            }
                        } else {
                            println!("[MESSAGE] From: {} (Encrypted {} bytes)", peer_id, envelope.payload.len());
                        }
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
            // Read from stdin
            line = tokio::io::AsyncBufReadExt::read_line(&mut stdin, &mut line_buf) => {
                match line {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        let cmd = line_buf.trim();
                        if cmd.starts_with("/send ") {
                            let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
                            if parts.len() == 3 {
                                let peer_id = parts[1];
                                let msg_text = parts[2];
                                println!("Sending to {}: {}", peer_id, msg_text);
                                
                                let msg = Message::text(msg_text);
                                let envelope = MessageEnvelope::unencrypted(&node.peer_id(), &msg);

                                if let Err(e) = node.send_message(peer_id.to_string(), envelope).await {
                                     println!("[ERROR] Send failed: {}", e);
                                } else {
                                     println!("[SENT] Message sent");
                                }
                            } else {
                                println!("Usage: /send <peer_id> <message>");
                            }
                        } else if cmd == "/peers" {
                             let peers = node.get_peers().await;
                             println!("\n[STATUS] Connected peers: {}", peers.len());
                             for p in &peers {
                                 println!("  - {}", p.peer_id);
                             }
                        } else if cmd == "/id" {
                             println!("My Peer ID: {}", node.peer_id());
                        } else {
                            println!("Unknown command. Available: /send <peer> <msg>, /peers, /id");
                        }
                        line_buf.clear();
                    }
                    Err(e) => {
                        println!("Error reading stdin: {}", e);
                        break;
                    }
                }
            }
        }
    }
}
