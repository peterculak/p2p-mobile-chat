//! P2P Test CLI - Run a node with full encryption and privacy support

use securechat_core::network::{P2PNode, NetworkConfig, NodeEvent};
use securechat_core::messaging::{MessagingManager, MessagingEvent};
use securechat_core::privacy::{PrivacyManager, PrivacyConfig, PrivacyEvent};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .init();

    println!("=== P2P Test Node (Encrypted + Privacy) ===\n");

    let config = NetworkConfig::local_only();
    let mut node = P2PNode::new(config.clone());
    
    // Create messaging manager
    let mut messaging = MessagingManager::new(&node.peer_id());
    
    // Create privacy manager (relay enabled by default, onion routing off by default)
    let privacy_config = PrivacyConfig::default();
    let mut privacy = PrivacyManager::new(privacy_config);
    
    let stdin = tokio::io::stdin();
    let mut stdin = tokio::io::BufReader::new(stdin);
    let mut line_buf = String::new();

    println!("Peer ID: {}", node.peer_id());
    println!("Relay Public Key: {}", hex::encode(privacy.relay_public_key()));
    
    // Get and display our prekey bundle
    let bundle = messaging.get_prekey_bundle();
    let peer_id = node.peer_id();
    let identity = hex::encode(bundle.identity_key);
    let verifying = hex::encode(bundle.identity_verifying_key.as_bytes());
    let signed_prekey = hex::encode(bundle.signed_prekey);
    let signature = hex::encode(bundle.signed_prekey_signature.to_bytes());
    
    println!("\n=== COPY-PASTE COMMANDS FOR OTHER TERMINAL ===\n");
    println!("/session {} {} {} {} {}", peer_id, identity, verifying, signed_prekey, signature);
    // println!("/relay {} {}", peer_id, hex::encode(privacy.relay_public_key())); // RELAY AUTO-DISCOVERY NOW ENABLED
    println!("/send {} Hello from other terminal!", peer_id);
    println!("\n===============================================\n");
    
    println!("Starting node...");

    if let Err(e) = node.start(config).await {
        eprintln!("Failed to start: {}", e);
        return;
    }

    println!("Node started! Listening for peers...\n");
    println!("Commands:");
    println!("  /session  - Establish encrypted session");
    println!("  /send     - Send encrypted message");
    println!("  /relay    - Register a relay node");
    println!("  /onion    - Toggle onion routing");
    println!("  /privacy  - Show privacy status");
    println!("  /contacts /peers /id");
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
                            // Auto-dial the discovered peer
                            if let Err(e) = node.dial(addr).await {
                                println!("[ERROR] Failed to dial {}: {}", addr, e);
                            }
                        }
                    }
                    Some(NodeEvent::PeerConnected { peer_id }) => {
                        println!("[CONNECTED] {}", peer_id);
                        
                        // AUTO-DISCOVERY: Announce ourselves as a relay
                        use securechat_core::messaging::protocol::{Message, MessageEnvelope};
                        let my_relay_key = hex::encode(privacy.relay_public_key());
                        let announcement = Message::relay_announcement(&my_relay_key);
                        let envelope = MessageEnvelope::unencrypted(&node.peer_id(), &announcement);
                        
                        // We need to send this raw message immediately
                        // This bypasses MessagingManager queue to ensure immediate delivery upon connection
                        if let Err(e) = node.send_raw_message(peer_id.clone(), envelope.to_bytes()).await {
                            println!("[ERROR] Failed to announce relay key: {}", e);
                        } else {
                            println!("[AUTO] Announced relay capability to {}", peer_id);
                        }
                    }
                    Some(NodeEvent::PeerDisconnected { peer_id }) => {
                        println!("[DISCONNECTED] {}", peer_id);
                        // Remove from relay registry
                        privacy.unregister_relay(&peer_id);
                    }
                    Some(NodeEvent::MessageReceived { peer_id, envelope }) => {
                        // Check message type for OnionPacket
                        let mut processed = false;
                        
                        info!("Received envelope from {} (sender in envelope: {})", peer_id, envelope.sender_peer_id);
                        
                        // Parse envelope to check message type
                        if let Ok(msg) = securechat_core::messaging::protocol::Message::from_bytes(&envelope.payload) {
                            info!("Parsed inner message: type={:?}, id={}", msg.message_type, msg.id);
                            if msg.message_type == securechat_core::messaging::protocol::MessageType::OnionPacket {
                                use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
                                // Extract base64 content
                                if let Ok(packet_bytes) = BASE64.decode(&msg.content) {
                                    info!("Processing onion packet ({} bytes)", packet_bytes.len());
                                    // Process as onion packet
                                    let is_onion = privacy.process_incoming(&packet_bytes);
                                    processed = true;
                                    if !is_onion {
                                         info!("[WARN] Privacy manager rejected packet as non-onion (wrong size?)");
                                    }
                                } else {
                                    info!("[ERROR] Failed to base64 decode onion packet content");
                                }
                            }
                        } else {
                            info!("[ERROR] Failed to parse payload as Message from {}", peer_id);
                        }
                        
                        if !processed {
                            info!("Message not processed as onion, handing to messaging layer");
                            // Regular encrypted message (or non-onion)
                            if let Err(e) = messaging.handle_incoming(&peer_id, &envelope.to_bytes()) {
                                println!("[ERROR] Failed to handle message: {}", e);
                            }
                        }
                        
                        // Process privacy events
                        while let Some(privacy_event) = privacy.next_event() {
                            match privacy_event {
                                 PrivacyEvent::RelayPacket { next_peer_id, packet_bytes, delay_ms } => {
                                    info!("[RELAY] Forwarding onion packet to {} (delay: {}ms)", next_peer_id, delay_ms);
                                    if delay_ms > 0 {
                                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                                    }
                                    // Wrap in OnionPacket envelope
                                    let onion_msg = securechat_core::messaging::protocol::Message::onion_packet(&packet_bytes);
                                    let envelope = securechat_core::messaging::protocol::MessageEnvelope::unencrypted(&node.peer_id(), &onion_msg);
                                    
                                    if let Err(e) = node.send_message(next_peer_id.clone(), envelope).await {
                                        println!("[ERROR] Relay forward failed: {}", e);
                                    }
                                }
                                PrivacyEvent::DeliverPayload { next_peer_id, payload } => {
                                    info!("[EXIT_NODE] Delivering raw payload to {}", next_peer_id);
                                    // The payload is already a MessageEnvelope (Signal-encrypted)
                                    if let Ok(envelope) = securechat_core::messaging::protocol::MessageEnvelope::from_bytes(&payload) {
                                        if let Err(e) = node.send_message(next_peer_id, envelope).await {
                                            println!("[ERROR] Exit node delivery failed: {}", e);
                                        }
                                    } else {
                                        println!("[ERROR] Exit node: decrypted payload is not a valid MessageEnvelope");
                                    }
                                }
                                PrivacyEvent::PacketDelivered { payload } => {
                                    info!("[DESTINATION] Onion packet DELIVERED to us! Size: {} bytes", payload.len());
                                    // Process as regular message
                                    if let Err(e) = messaging.handle_incoming(&peer_id, &payload) {
                                        println!("[ERROR] Failed to handle onion message: {}", e);
                                    }
                                }
                                PrivacyEvent::CircuitBuilt { circuit_id, hops } => {
                                    println!("[CIRCUIT] Built #{} with {} hops", circuit_id, hops);
                                }
                                PrivacyEvent::Error { message } => {
                                    println!("[PRIVACY_ERROR] {}", message);
                                }
                            }
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
                        MessagingEvent::RelayAnnouncement { peer_id, public_key_hex } => {
                            // AUTO-DISCOVERY: Register relay
                            if let Ok(key_bytes) = hex::decode(&public_key_hex) {
                                if key_bytes.len() == 32 {
                                    let mut key = [0u8; 32];
                                    key.copy_from_slice(&key_bytes);
                                    privacy.register_relay(&peer_id, key);
                                    println!("[AUTO] Registered relay {} (total: {})", peer_id, privacy.relay_count());
                                    
                                    // Auto-enable if we have enough relays
                                    if privacy.can_build_circuit() && !privacy.is_onion_enabled() {
                                        privacy.set_onion_enabled(true);
                                        println!("[AUTO] Enabled onion routing (3+ relays found)");
                                    }
                                }
                            }
                        }
                        MessagingEvent::OnionPacketReceived { data } => {
                            info!("Onion packet received via messaging (internal detection)");
                            privacy.process_incoming(&data);
                        }
                    }
                }
                
                // Send outgoing messages
                while let Some(outgoing) = messaging.next_outgoing() {
                    // If onion routing is enabled, wrap the message
                    if privacy.is_onion_enabled() && privacy.can_build_circuit() {
                        if let Some(onion) = privacy.wrap_message(&outgoing.data, &outgoing.peer_id) {
                            println!("[ONION] Sending via {} ({} hop circuit)", onion.entry_peer_id, 3);
                            let onion_msg = securechat_core::messaging::protocol::Message::onion_packet(&onion.packet_bytes);
                            let envelope = securechat_core::messaging::protocol::MessageEnvelope::unencrypted(&node.peer_id(), &onion_msg);
                            
                            if let Err(e) = node.send_message(onion.entry_peer_id, envelope).await {
                                println!("[ERROR] Onion send failed: {}", e);
                            }
                        } else {
                            // Fallback to direct send
                            println!("[DIRECT] Onion failed, sending directly");
                            if let Err(e) = node.send_raw_message(outgoing.peer_id.clone(), outgoing.data).await {
                                println!("[ERROR] Failed to send: {}", e);
                            }
                        }
                    } else {
                        // Direct send
                        if let Err(e) = node.send_raw_message(outgoing.peer_id.clone(), outgoing.data).await {
                            println!("[ERROR] Failed to send: {}", e);
                        }
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
                        } else if cmd.starts_with("/relay ") {
                            // /relay <peer_id> <public_key_hex>
                            let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
                            if parts.len() == 3 {
                                let peer_id = parts[1];
                                let public_key_hex = parts[2];
                                
                                if let Ok(key_bytes) = hex::decode(public_key_hex) {
                                    if key_bytes.len() == 32 {
                                        let mut public_key = [0u8; 32];
                                        public_key.copy_from_slice(&key_bytes);
                                        privacy.register_relay(peer_id, public_key);
                                        println!("[RELAY] Registered {} (total: {})", peer_id, privacy.relay_count());
                                        if privacy.can_build_circuit() {
                                            println!("[INFO] Can now build onion circuits! Use /onion on to enable.");
                                        }
                                    } else {
                                        println!("[ERROR] Public key must be 32 bytes (64 hex chars)");
                                    }
                                } else {
                                    println!("[ERROR] Invalid hex string");
                                }
                            } else {
                                println!("Usage: /relay <peer_id> <public_key_hex>");
                            }
                        } else if cmd == "/onion on" {
                            if privacy.can_build_circuit() {
                                privacy.set_onion_enabled(true);
                                println!("[PRIVACY] Onion routing ENABLED");
                            } else {
                                println!("[ERROR] Not enough relays. Need {} relays, have {}", 2, privacy.relay_count());
                                println!("Use /relay to register relay nodes first.");
                            }
                        } else if cmd == "/onion off" {
                            privacy.set_onion_enabled(false);
                            println!("[PRIVACY] Onion routing DISABLED");
                        } else if cmd == "/onion" {
                            println!("Usage: /onion on|off");
                        } else if cmd == "/privacy" {
                            let (relayed, delivered, relay_enabled) = privacy.relay_stats();
                            println!("\n[PRIVACY STATUS]");
                            println!("  Onion routing: {}", if privacy.is_onion_enabled() { "ON" } else { "OFF" });
                            println!("  Relay mode: {}", if relay_enabled { "ON" } else { "OFF" });
                            println!("  Known relays: {}", privacy.relay_count());
                            println!("  Can build circuit: {}", if privacy.can_build_circuit() { "YES" } else { "NO (need 2 relays)" });
                            println!("  Packets relayed: {}", relayed);
                            println!("  Packets delivered: {}", delivered);
                            println!("  My relay key: {}", hex::encode(privacy.relay_public_key()));
                        } else if cmd.starts_with("/send ") {
                            let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
                            if parts.len() == 3 {
                                let peer_id = parts[1];
                                let msg_text = parts[2];
                                
                                if privacy.is_onion_enabled() {
                                    // Use onion routing
                                    match messaging.prepare_encrypted_message(peer_id, msg_text) {
                                        Ok((_msg_id, encrypted_payload)) => {
                                            match privacy.wrap_message(&encrypted_payload, peer_id) {
                                                Some(packet) => {
                                                    // Send via onion
                                                    let first_hop = packet.entry_peer_id.clone();
                                                    let packet_bytes = packet.packet_bytes;
                                                    
                                                    // Wrap in OnionPacket envelope
                                                    let onion_msg = securechat_core::messaging::protocol::Message::onion_packet(&packet_bytes);
                                                    let envelope = securechat_core::messaging::protocol::MessageEnvelope::unencrypted(&node.peer_id(), &onion_msg);

                                                    match node.send_message(first_hop.clone(), envelope).await {
                                                        Ok(_) => {
                                                            println!("[ONION] Sending via {} (circuit id: ???)", first_hop); 
                                                            // We should probably track the message ID too?
                                                            // For now just print success
                                                        }
                                                        Err(e) => println!("[ERROR] Failed to send onion packet: {}", e),
                                                    }
                                                }
                                                None => println!("[ERROR] Failed to build circuit: Not enough relays or onion routing disabled"),
                                            }
                                        }
                                        Err(e) => println!("[ERROR] Encryption failed: {:?}", e),
                                    }
                                } else {
                                    // Direct send
                                    match messaging.send_message(peer_id, msg_text) {
                                        Ok(msg_id) => {
                                            println!("[SENDING] Message {} to {} (direct)", msg_id, peer_id);
                                            // Actually send the queued message
                                            while let Some(outgoing) = messaging.next_outgoing() {
                                                if let Err(e) = node.send_raw_message(outgoing.peer_id.clone(), outgoing.data).await {
                                                    println!("[ERROR] Network send failed: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            println!("[ERROR] Send failed: {}", e);
                                            println!("Hint: Make sure you've added this peer as a contact with /add (or exchanged session)");
                                        }
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
                            println!("My Relay Key: {}", hex::encode(privacy.relay_public_key()));
                        } else if cmd.starts_with("/session ") {
                            // /session <peer_id> <identity_x25519_hex> <verifying_ed25519_hex> <signed_prekey_hex> <signature_hex>
                            let parts: Vec<&str> = cmd.splitn(6, ' ').collect();
                            if parts.len() == 6 {
                                let peer_id = parts[1];
                                let identity_hex = parts[2];
                                let verifying_hex = parts[3];
                                let signed_prekey_hex = parts[4];
                                let signature_hex = parts[5];
                                
                                match (
                                    hex::decode(identity_hex),
                                    hex::decode(verifying_hex),
                                    hex::decode(signed_prekey_hex),
                                    hex::decode(signature_hex),
                                ) {
                                    (Ok(id), Ok(ver), Ok(spk), Ok(sig)) if id.len() == 32 && ver.len() == 32 && spk.len() == 32 && sig.len() == 64 => {
                                        // Build PreKeyBundle
                                        use securechat_core::crypto::keys::PreKeyBundle;
                                        use ed25519_dalek::{VerifyingKey, Signature};
                                        
                                        let mut identity_key = [0u8; 32];
                                        let mut verifying_key = [0u8; 32];
                                        let mut signed_prekey = [0u8; 32];
                                        let mut sig_bytes = [0u8; 64];
                                        identity_key.copy_from_slice(&id);
                                        verifying_key.copy_from_slice(&ver);
                                        signed_prekey.copy_from_slice(&spk);
                                        sig_bytes.copy_from_slice(&sig);
                                        
                                        let bundle = PreKeyBundle {
                                            identity_key: identity_key.into(),
                                            identity_verifying_key: VerifyingKey::from_bytes(&verifying_key).unwrap(),
                                            signed_prekey: signed_prekey.into(),
                                            signed_prekey_id: 1,
                                            signed_prekey_signature: Signature::from_bytes(&sig_bytes),
                                            one_time_prekey: None,
                                        };
                                        
                                        // Add contact first
                                        messaging.add_contact(peer_id, peer_id, identity_key);
                                        
                                        // Then initiate session
                                        match messaging.initiate_session(peer_id, &bundle) {
                                            Ok(_) => println!("[SESSION] Established with {}", peer_id),
                                            Err(e) => println!("[ERROR] Session failed: {}", e),
                                        }
                                        
                                        // Send session init message
                                        while let Some(outgoing) = messaging.next_outgoing() {
                                            if let Err(e) = node.send_raw_message(outgoing.peer_id.clone(), outgoing.data).await {
                                                println!("[ERROR] Failed to send session init: {}", e);
                                            }
                                        }
                                    }
                                    _ => println!("[ERROR] Invalid hex keys. Need 32-byte identity, 32-byte verifying, 32-byte prekey, 64-byte signature"),
                                }
                            } else {
                                println!("Usage: /session <peer_id> <identity_x25519> <verifying_ed25519> <signed_prekey> <signature>");
                            }
                        } else if cmd == "/help" || cmd.is_empty() {
                            println!("\nAvailable commands:");
                            println!("  /session <peer_id> <identity> <verifying> <prekey> <sig>  - Establish encrypted session");
                            println!("  /send <peer_id> <message>                                 - Send encrypted message");
                            println!("  /relay <peer_id> <public_key_hex>                        - Register a relay node");
                            println!("  /onion on|off                                            - Toggle onion routing");
                            println!("  /privacy                                                 - Show privacy status");
                            println!("  /contacts                                                - List contacts");
                            println!("  /peers                                                   - List connected peers");
                            println!("  /id                                                      - Show my IDs/keys");
                            println!("  /help                                                    - Show this help");
                        } else {
                            println!("Unknown command. Type /help for available commands.");
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
