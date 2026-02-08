//! P2P Test CLI - Run a node with full encryption support

use securechat_core::network::{P2PNode, NetworkConfig, NodeEvent};
use securechat_core::messaging::{MessagingManager, MessagingEvent};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .init();

    println!("=== P2P Test Node (Encrypted) ===\n");

    let config = NetworkConfig::local_only();
    let mut node = P2PNode::new(config.clone());
    
    // Create messaging manager
    let mut messaging = MessagingManager::new(&node.peer_id());
    
    let stdin = tokio::io::stdin();
    let mut stdin = tokio::io::BufReader::new(stdin);
    let mut line_buf = String::new();

    println!("Peer ID: {}", node.peer_id());
    println!("Identity Key: {}", node.public_key_hex());
    
    // Get and display our prekey bundle
    let bundle = messaging.get_prekey_bundle();
    println!("PreKey Bundle (for contacts to add you):");
    println!("  Identity: {}", hex::encode(bundle.identity_key));
    println!("  Signed PreKey: {}", hex::encode(bundle.signed_prekey));
    println!("  Signature: {}", hex::encode(bundle.signed_prekey_signature.to_bytes()));
    if let Some((id, otpk)) = bundle.one_time_prekey {
        println!("  One-Time PreKey: {} (ID: {})", hex::encode(otpk.as_bytes()), id);
    }
    
    println!("\nStarting node...");

    if let Err(e) = node.start(config).await {
        eprintln!("Failed to start: {}", e);
        return;
    }

    println!("Node started! Listening for peers...\n");
    println!("Commands:");
    println!("  /add <peer_id> <name> <identity_key_hex>");
    println!("  /send <peer_id> <message>");
    println!("  /contacts");
    println!("  /peers");
    println!("  /id\n");
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
                        // Pass to messaging manager
                        if let Err(e) = messaging.handle_incoming(&peer_id, &envelope.to_bytes()) {
                            println!("[ERROR] Failed to handle message: {}", e);
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
                
                // Process messaging events
                while let Some(msg_event) = messaging.next_event() {
                    match msg_event {
                        MessagingEvent::MessageReceived { from_peer_id, message } => {
                            println!("[MESSAGE] From {}: {}", from_peer_id, message.content);
                        }
                        MessagingEvent::MessageSent { to_peer_id, message_id } => {
                            println!("[SENT] Message {} to {}", message_id, to_peer_id);
                        }
                        MessagingEvent::SessionEstablished { peer_id } => {
                            println!("[SESSION] Established with {}", peer_id);
                        }
                        MessagingEvent::DeliveryReceipt { peer_id, message_id } => {
                            println!("[RECEIPT] {} acknowledged {}", peer_id, message_id);
                        }
                        MessagingEvent::Error { message } => {
                            println!("[MSG_ERROR] {}", message);
                        }
                    }
                }
                
                // Send outgoing messages
                while let Some(outgoing) = messaging.next_outgoing() {
                    if let Err(e) = node.send_raw_message(outgoing.peer_id.clone(), outgoing.data).await {
                        println!("[ERROR] Failed to send: {}", e);
                    }
                }
            }
            // Read from stdin
            line = tokio::io::AsyncBufReadExt::read_line(&mut stdin, &mut line_buf) => {
                match line {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        let cmd = line_buf.trim();
                        if cmd.starts_with("/add ") {
                            let parts: Vec<&str> = cmd.splitn(4, ' ').collect();
                            if parts.len() == 4 {
                                let peer_id = parts[1];
                                let name = parts[2];
                                let identity_hex = parts[3];
                                
                                if let Ok(identity_bytes) = hex::decode(identity_hex) {
                                    if identity_bytes.len() == 32 {
                                        let mut identity_key = [0u8; 32];
                                        identity_key.copy_from_slice(&identity_bytes);
                                        messaging.add_contact(peer_id, name, identity_key);
                                        println!("[CONTACT] Added {} ({})", name, peer_id);
                                    } else {
                                        println!("[ERROR] Identity key must be 32 bytes (64 hex chars)");
                                    }
                                } else {
                                    println!("[ERROR] Invalid hex string");
                                }
                            } else {
                                println!("Usage: /add <peer_id> <name> <identity_key_hex>");
                            }
                        } else if cmd.starts_with("/send ") {
                            let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
                            if parts.len() == 3 {
                                let peer_id = parts[1];
                                let msg_text = parts[2];
                                
                                match messaging.send_message(peer_id, msg_text) {
                                    Ok(msg_id) => {
                                        println!("[SENDING] Message {} to {}", msg_id, peer_id);
                                    }
                                    Err(e) => {
                                        println!("[ERROR] Send failed: {}", e);
                                        println!("Hint: Make sure you've added this peer as a contact with /add");
                                    }
                                }
                            } else {
                                println!("Usage: /send <peer_id> <message>");
                            }
                        } else if cmd == "/contacts" {
                            let contacts = messaging.list_contacts();
                            println!("\n[CONTACTS] {} total", contacts.len());
                            for c in &contacts {
                                println!("  - {} ({})", c.name, c.peer_id);
                                println!("    Session: {}", if c.session_established { "✓" } else { "✗" });
                            }
                        } else if cmd == "/peers" {
                            let peers = node.get_peers().await;
                            println!("\n[PEERS] Connected: {}", peers.len());
                            for p in &peers {
                                println!("  - {}", p.peer_id);
                            }
                        } else if cmd == "/id" {
                            println!("My Peer ID: {}", node.peer_id());
                            println!("My Identity Key: {}", node.public_key_hex());
                        } else {
                            println!("Unknown command. Available:");
                            println!("  /add <peer_id> <name> <identity_key_hex>");
                            println!("  /send <peer_id> <message>");
                            println!("  /contacts");
                            println!("  /peers");
                            println!("  /id");
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
