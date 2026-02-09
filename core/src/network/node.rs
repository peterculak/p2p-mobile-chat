//! P2P Node implementation

use crate::network::behaviour::{NodeBehaviour, BehaviourEvent};
use crate::network::config::NetworkConfig;
use crate::network::persistence::PeerStore;
use crate::messaging::{Message, MessageEnvelope, MessageType};
use crate::network::chat::{ChatRequest, ChatResponse};
use crate::privacy::manager::PrivacyEvent;

use libp2p::{
    core::transport::upgrade::Version,
    core::muxing::StreamMuxerBox,
    identity,
    noise,
    identify, kad, autonat, relay, dcutr,
    request_response::{self, ResponseChannel, OutboundRequestId},
    swarm::{SwarmEvent, Swarm},
    tcp, quic, dns, yamux, Multiaddr, PeerId, Transport,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock, oneshot};
use tracing::{info, warn, debug, error};
use futures::future::Either;
use base64::Engine;

/// Information about a discovered peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: String,
    pub addresses: Vec<String>,
}

/// Events emitted by the P2P node
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// Node started listening on an address
    Listening { address: String },
    /// New peer discovered
    PeerDiscovered { peer: PeerInfo },
    /// Peer disconnected
    PeerDisconnected { peer_id: String },
    /// Peer connected (TCP/Noise handshake complete)
    PeerConnected { peer_id: String },
    /// Error occurred
    Error { message: String },
    /// Message received from peer
    MessageReceived { peer_id: String, envelope: MessageEnvelope },
}

/// Commands that can be sent to the node
enum NodeCommand {
    /// Stop the node
    Stop,
    /// Get connected peers
    GetPeers(oneshot::Sender<Vec<PeerInfo>>),
    /// Dial a peer
    Dial(String),
    /// Send a message to a peer
    SendMessage { peer_id: String, envelope: MessageEnvelope },
}

/// A P2P network node
pub struct P2PNode {
    /// Our peer ID
    local_peer_id: PeerId,
    /// Local keypair
    local_key: identity::Keypair,
    /// Local peer ID as hex string
    peer_id_string: String,
    /// Command sender for controlling the node
    command_tx: Option<mpsc::Sender<NodeCommand>>,
    /// Event receiver for node events
    event_rx: Option<mpsc::Receiver<NodeEvent>>,
    /// Connected peers
    connected_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Running state
    is_running: Arc<RwLock<bool>>,
    /// Path for persisting peer data
    persistence_path: Option<String>,
    /// Privacy Manager for Onion Routing
    privacy_manager: Arc<RwLock<crate::privacy::manager::PrivacyManager>>,
}

impl P2PNode {
    /// Create a new P2P node with the given configuration
    pub fn new(_config: NetworkConfig) -> Self {
        // Generate a new identity (in production, we'd use stored keys)
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        Self {
            local_peer_id,
            local_key,
            peer_id_string: local_peer_id.to_string(),
            command_tx: None,
            event_rx: None,
            connected_peers: Arc::new(RwLock::new(HashSet::new())),
            is_running: Arc::new(RwLock::new(false)),
            persistence_path: None,
            privacy_manager: Arc::new(RwLock::new(crate::privacy::manager::PrivacyManager::new(
                crate::privacy::manager::PrivacyConfig::default()
            ))),
        }
    }

    /// Set persistence path for the node
    pub fn with_persistence(mut self, path: String) -> Self {
        self.persistence_path = Some(path);
        self
    }

    /// Set the identity keypair for the node
    pub fn with_identity(mut self, key: identity::Keypair) -> Self {
        self.local_peer_id = PeerId::from(key.public());
        self.peer_id_string = self.local_peer_id.to_string();
        self.local_key = key;
        self
    }
    
    /// Get the public key as hex string (32 bytes Ed25519)
    pub fn public_key_hex(&self) -> String {
        let pub_key = self.local_key.public();
        if let Ok(ed25519_key) = pub_key.try_into_ed25519() {
             hex::encode(ed25519_key.to_bytes())
        } else {
             // Fallback or error, but we forced Ed25519 above
             String::new()
        }
    }

    /// Get the local peer ID as a string
    pub fn peer_id(&self) -> &str {
        &self.peer_id_string
    }

    /// Check if the node is running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// Start the P2P node
    pub async fn start(&mut self, config: NetworkConfig) -> Result<(), String> {
        if *self.is_running.read().await {
            return Err("Node already running".to_string());
        }
        
        // Configure Privacy Manager
        self.privacy_manager.write().await.set_onion_enabled(config.enable_onion_routing);

        let local_key = self.local_key.clone();
        let local_peer_id = self.local_peer_id;

        // Create transport
        let upgraded_tcp = match dns::tokio::Transport::system(tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))) {
            Ok(dns_tcp) => {
                dns_tcp.upgrade(Version::V1)
                    .authenticate(noise::Config::new(&local_key).map_err(|e| e.to_string())?)
                    .multiplex(yamux::Config::default())
                    .boxed()
            },
            Err(e) => {
                warn!("Failed to create DNS transport: {}. Falling back to plain TCP.", e);
                tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
                    .upgrade(Version::V1)
                    .authenticate(noise::Config::new(&local_key).map_err(|e| e.to_string())?)
                    .multiplex(yamux::Config::default())
                    .boxed()
            }
        };

        let quic_transport = quic::tokio::Transport::new(quic::Config::new(&local_key));
        
        let transport = upgraded_tcp
            .or_transport(quic_transport)
            .map(|either, _| match either {
                Either::Left(t) => t,
                Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            })
            .boxed();

        // Create behaviour
        let (behaviour, relay_transport) = NodeBehaviour::new(local_peer_id, local_key.public());
        
        let relay_transport = relay_transport
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&local_key).map_err(|e| e.to_string())?)
            .multiplex(yamux::Config::default())
            .boxed();

        // Integrate Relay transport (allows listening/dialing via relays)
        let transport = transport
             .or_transport(relay_transport)
             .map(|either, _| match either {
                 Either::Left(t) => t,
                 Either::Right(t) => t,
             })
             .boxed();

        // Create swarm
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(1800)), // 30 minutes
        );

        // Listen on configured port (TCP)
        let listen_addr_tcp: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", config.listen_port)
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| e.to_string())?;
        swarm.listen_on(listen_addr_tcp).map_err(|e| e.to_string())?;

        // Listen on configured port (QUIC/UDP)
        let listen_addr_quic: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", config.listen_port)
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| e.to_string())?;
        swarm.listen_on(listen_addr_quic).map_err(|e| e.to_string())?;

        // Listen on any connected relays
        if let Ok(relay_addr) = "/p2p-circuit".parse::<Multiaddr>() {
            let _ = swarm.listen_on(relay_addr);
            info!("Relay: Enabled automatic listening on circuits.");
        }

        // Create channels for communication
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<NodeCommand>(32);
        let (event_tx, event_rx) = mpsc::channel::<NodeEvent>(64);

        self.command_tx = Some(cmd_tx);
        self.event_rx = Some(event_rx);

        let connected_peers = self.connected_peers.clone();
        let is_running = self.is_running.clone();
        let privacy_manager = self.privacy_manager.clone();

        *is_running.write().await = true;

        let persistence_path = self.persistence_path.clone();
        let config_clone = config.clone();
        
        tokio::spawn(async move {
            let mut node_swarm = swarm;

            // Dial bootstrap peers and add to Kademlia
            warn!("Bootstrap: Initializing with {} peers from hardcoded list", config_clone.bootstrap_peers.len());
            for (i, peer_addr) in config_clone.bootstrap_peers.iter().enumerate() {
                if let Ok(multiaddr) = peer_addr.parse::<Multiaddr>() {
                    info!("Bootstrap [{}]: Dialing {}", i, multiaddr);
                    // Extract PeerID from multiaddr if present
                    if let Some(peer_id) = multiaddr.iter().last().and_then(|p| {
                        if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
                            Some(peer_id)
                        } else {
                            None
                        }
                    }) {
                        debug!("Bootstrap [{}]: Adding PeerID {} to Kademlia", i, peer_id);
                        node_swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr.clone());
                    } else {
                        warn!("Bootstrap [{}]: No PeerID found in address {}", i, multiaddr);
                    }
                    if let Err(e) = node_swarm.dial(multiaddr) {
                        warn!("Bootstrap [{}]: Immediate dial failure: {:?}", i, e);
                    }
                } else {
                    error!("Bootstrap [{}]: Failed to parse address {}", i, peer_addr);
                }
            }

            // Start Kademlia bootstrap
            info!("Kademlia: Triggering initial DHT bootstrap...");
            if let Err(e) = node_swarm.behaviour_mut().kad.bootstrap() {
                warn!("Kademlia: Initial bootstrap failed to start: {e}");
            }
            
            // Re-connect to known peers
            // Re-connect to known peers
            // DISABLED FOR PRIVATE RELAY TRANSITION (To clear old global peers)
            /*
            if let Some(path) = &persistence_path {
                let store = PeerStore::load(path);
                for (peer_id_str, peer_data) in store.peers {
                    if let Ok(peer_id) = peer_id_str.parse::<PeerId>() {
                        for addr_str in peer_data.addresses {
                            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                                info!("Organic Mesh: Attempting to reconnect to saved peer {} at {}", peer_id, addr);
                                let _ = node_swarm.dial(addr);
                            }
                        }
                    }
                }
            }
            */
            
            let mut peer_store = if let Some(path) = &persistence_path {
                PeerStore::load(path)
            } else {
                PeerStore::default()
            };

            // Periodic bootstrap timer
            let mut bootstrap_timer = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                tokio::select! {
                    _ = bootstrap_timer.tick() => {
                        let connected_count = node_swarm.connected_peers().count();
                        if connected_count < 2 {
                            info!("Running periodic Kademlia bootstrap (connected to {} peers)...", connected_count);
                            let _ = node_swarm.behaviour_mut().kad.bootstrap();
                        }
                    }
                    event = node_swarm.select_next_some() => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                info!("Listening on {address}");
                                let _ = event_tx.send(NodeEvent::Listening {
                                    address: address.to_string(),
                                }).await;
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns_event)) => {
                                match mdns_event {
                                    libp2p::mdns::Event::Discovered(peers) => {
                                        for (peer_id, addr) in peers {
                                            info!("mDNS discovered peer: {peer_id} at {addr}");
                                            node_swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                            connected_peers.write().await.insert(peer_id);
                                            let peer = PeerInfo {
                                                peer_id: peer_id.to_string(),
                                                addresses: vec![addr.to_string()],
                                            };
                                            // Update persistence if enabled
                                            if let Some(path) = &persistence_path {
                                                peer_store.update_peer(peer.peer_id.clone(), peer.addresses.clone());
                                                let _ = peer_store.save(path);
                                            }

                                            let _ = event_tx.send(NodeEvent::PeerDiscovered { peer }).await;
                                        }
                                    }
                                    libp2p::mdns::Event::Expired(peers) => {
                                        for (peer_id, _) in peers {
                                            debug!("mDNS peer expired: {peer_id}");
                                            connected_peers.write().await.remove(&peer_id);
                                            let _ = event_tx.send(NodeEvent::PeerDisconnected {
                                                peer_id: peer_id.to_string(),
                                            }).await;
                                        }
                                    }
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad_event)) => {
                                match kad_event {
                                    kad::Event::RoutingUpdated { peer, is_new_peer, .. } => {
                                        if is_new_peer {
                                            info!("Kademlia: Successfully added NEW peer to routing table: {peer}");
                                        } else {
                                            debug!("Kademlia: Updated routing table for peer: {peer}");
                                        }
                                    }
                                    kad::Event::OutboundQueryProgressed { result, .. } => {
                                        match result {
                                            kad::QueryResult::Bootstrap(Ok(bootstrap)) => {
                                                info!("Kademlia: Bootstrap SUCCESS. Found {} new peers.", bootstrap.num_remaining);
                                            }
                                            kad::QueryResult::Bootstrap(Err(e)) => {
                                                warn!("Kademlia: Bootstrap ATTEMPT failed or timed out: {:?}", e);
                                            }
                                            _ => {}
                                        }
                                    }
                                    _ => {
                                        debug!("Kademlia event: {:?}", kad_event);
                                    }
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                                info!("Identify: Received info from {peer_id} with {} addresses", info.listen_addrs.len());
                                let addresses: Vec<String> = info.listen_addrs.iter().map(|a: &Multiaddr| a.to_string()).collect();
                                
                                // Update persistence
                                if let Some(path) = &persistence_path {
                                    peer_store.update_peer(peer_id.to_string(), addresses.clone());
                                    let _ = peer_store.save(path);
                                }
                                
                                // Also add to Kademlia so we can find them later
                                for addr in info.listen_addrs.clone() {
                                    node_swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                                }

                                // EMIT EVENT for UI
                                let peer = PeerInfo {
                                    peer_id: peer_id.to_string(),
                                    addresses,
                                };
                                let _ = event_tx.send(NodeEvent::PeerDiscovered { peer }).await;
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Ping(ping_event)) => {
                                debug!("Ping: {:?}", ping_event);
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                info!("Connected to peer: {peer_id}");
                                connected_peers.write().await.insert(peer_id);
                                let _ = event_tx.send(NodeEvent::PeerConnected {
                                    peer_id: peer_id.to_string(),
                                }).await;
                            }
                            SwarmEvent::IncomingConnectionError { error, .. } => {
                                error!("Incoming connection error: {:?}", error);
                            }
                            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                                match peer_id {
                                    Some(pid) => error!("Outgoing connection error to peer {pid}: {:?}", error),
                                    None => error!("Outgoing connection error to unknown peer: {:?}", error),
                                }
                            }
                            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                                info!("Disconnected from peer: {peer_id}. Cause: {:?}", cause);
                                connected_peers.write().await.remove(&peer_id);
                                let _ = event_tx.send(NodeEvent::PeerDisconnected {
                                    peer_id: peer_id.to_string(),
                                }).await;
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Autonat(autonat::Event::StatusChanged { old: _, new })) => {
                                info!("AutoNAT: Status changed to {:?}", new);
                                if let autonat::NatStatus::Public(_public_addr) = new {
                                    info!("Organic Mesh: Public IP detected! Acting as a RELAY for friends.");
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(relay_event)) => {
                                info!("Relay Client: {:?}", relay_event);
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::RelayServer(relay_event)) => {
                                debug!("Relay Server: {:?}", relay_event);
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(dcutr_event)) => {
                                info!("DCUTR: {:?}", dcutr_event);
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Chat(chat_event)) => {
                                match chat_event {
                                    request_response::Event::Message { peer, message } => {
                                        match message {
                                            request_response::Message::Request { request, channel, .. } => {
                                                info!("Received chat request from {peer}");
                                                // Send immediate Ack
                                                if let Err(e) = node_swarm.behaviour_mut().chat.send_response(channel, ChatResponse(vec![])) {
                                                    error!("Failed to send Chat Ack: {:?}", e);
                                                }
                                                
                                                let envelope = request.0;
                                                let mut manager = privacy_manager.write().await;
                                                let mut handled_as_onion = false;
                                                
                                                // Check for Relay Announcement
                                                if !envelope.encrypted {
                                                    if let Ok(msg) = Message::from_bytes(&envelope.payload) {
                                                        if msg.message_type == MessageType::RelayAnnouncement {
                                                            if let Ok(pub_key) = hex::decode(&msg.content) {
                                                                if pub_key.len() == 32 {
                                                                    let mut key_arr = [0u8; 32];
                                                                    key_arr.copy_from_slice(&pub_key);
                                                                    manager.register_relay(&peer.to_string(), key_arr);
                                                                    info!("Onion: Registered relay {} via announcement", peer);
                                                                    
                                                                    // Update UI/Events if needed
                                                                    let _ = event_tx.send(NodeEvent::PeerDiscovered { 
                                                                        peer: PeerInfo {
                                                                            peer_id: peer.to_string(),
                                                                            addresses: vec![], // Already connected
                                                                        }
                                                                    }).await;
                                                                    
                                                                    handled_as_onion = true;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                // Check if it's an Onion Packet
                                                if !envelope.encrypted {
                                                    if let Ok(msg) = Message::from_bytes(&envelope.payload) {
                                                        if msg.message_type == MessageType::OnionPacket {
                                                            if let Ok(packet_bytes) = base64::engine::general_purpose::STANDARD.decode(&msg.content) {
                                                                debug!("Onion: Processing packet from {}", peer);
                                                                if manager.process_incoming(&packet_bytes) {
                                                                    handled_as_onion = true;
                                                                    // Process events generated by privacy manager
                                                                    while let Some(event) = manager.next_event() {
                                                                        match event {
                                                                            PrivacyEvent::RelayPacket { next_peer_id, packet_bytes, .. } => {
                                                                                 if let Ok(next_peer) = next_peer_id.parse::<PeerId>() {
                                                                                     let fwd_msg = Message::onion_packet(&packet_bytes);
                                                                                     let fwd_env = MessageEnvelope::unencrypted(
                                                                                         &node_swarm.local_peer_id().to_string(),
                                                                                         &fwd_msg
                                                                                     );
                                                                                     debug!("Onion: Relaying to {}", next_peer);
                                                                                     node_swarm.behaviour_mut().chat.send_request(&next_peer, ChatRequest(fwd_env));
                                                                                 }
                                                                            }
                                                                            PrivacyEvent::DeliverPayload { next_peer_id, payload } => {
                                                                                if let Ok(next_peer) = next_peer_id.parse::<PeerId>() {
                                                                                    // Exit Node: Forward unwrapped payload to final dest
                                                                                    if let Ok(inner_env) = MessageEnvelope::from_bytes(&payload) {
                                                                                        debug!("Onion: Exit Node delivering to {}", next_peer);
                                                                                        node_swarm.behaviour_mut().chat.send_request(&next_peer, ChatRequest(inner_env));
                                                                                    }
                                                                                }
                                                                            }
                                                                            PrivacyEvent::PacketDelivered { payload } => {
                                                                                // Final Destination: It's for US!
                                                                                if let Ok(inner_env) = MessageEnvelope::from_bytes(&payload) {
                                                                                    debug!("Onion: Packet delivered to US!");
                                                                                    let _ = event_tx.send(NodeEvent::MessageReceived {
                                                                                        peer_id: peer.to_string(),
                                                                                        envelope: inner_env,
                                                                                    }).await;
                                                                                }
                                                                            }
                                                                            PrivacyEvent::Error { message } => {
                                                                                warn!("Onion Error: {}", message);
                                                                            }
                                                                            _ => {}
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                
                                                if !handled_as_onion {
                                                    // Standard Message
                                                    let _ = event_tx.send(NodeEvent::MessageReceived {
                                                        peer_id: peer.to_string(),
                                                        envelope,
                                                    }).await;
                                                }
                                            }
                                            request_response::Message::Response { .. } => {
                                                debug!("Received chat response (Ack) from {peer}");
                                            }
                                        }
                                    }
                                    request_response::Event::OutboundFailure { peer, request_id, error } => {
                                        error!("Outbound chat failure to {peer} (req {request_id}): {:?}", error);
                                    }
                                    request_response::Event::InboundFailure { peer, error, .. } => {
                                         error!("Inbound chat failure from {peer}: {:?}", error);
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                    // Handle commands
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(NodeCommand::Stop) => {
                                info!("Stopping P2P node");
                                break;
                            }
                            Some(NodeCommand::GetPeers(reply)) => {
                                let peers: Vec<PeerInfo> = connected_peers.read().await
                                    .iter()
                                    .map(|p| PeerInfo {
                                        peer_id: p.to_string(),
                                        addresses: vec![],
                                    })
                                    .collect();
                                let _ = reply.send(peers);
                            }
                            Some(NodeCommand::SendMessage { peer_id, envelope }) => {
                                let mut manager = privacy_manager.write().await;
                                
                                // Direct Send if Onion disabled or failed
                                let mut sent = false;
                                
                                if manager.is_onion_enabled() {
                                    let envelope_bytes = envelope.to_bytes();
                                    if let Some(onion) = manager.wrap_message(&envelope_bytes, &peer_id) {
                                        if let Ok(entry_peer) = onion.entry_peer_id.parse::<PeerId>() {
                                            let onion_msg = Message::onion_packet(&onion.packet_bytes);
                                            // Envelope sender is US, but payload is the onion packet
                                            let onion_envelope = MessageEnvelope::unencrypted(
                                                &node_swarm.local_peer_id().to_string(),
                                                &onion_msg,
                                            );
                                            debug!("Onion: Routing via {}", entry_peer);
                                            node_swarm.behaviour_mut().chat.send_request(&entry_peer, ChatRequest(onion_envelope));
                                            sent = true;
                                        }
                                    }
                                }
                                
                                if !sent {
                                    if let Ok(peer) = peer_id.parse::<PeerId>() {
                                        node_swarm.behaviour_mut().chat.send_request(&peer, ChatRequest(envelope));
                                    } else {
                                        warn!("Invalid peer ID: {}", peer_id);
                                    }
                                }
                            }
                            Some(NodeCommand::Dial(addr)) => {
                                if let Ok(multiaddr) = addr.parse::<Multiaddr>() {
                                    if let Err(e) = node_swarm.dial(multiaddr) {
                                        warn!("Failed to dial: {e}");
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            *is_running.write().await = false;
        });

        info!("P2P node started with peer ID: {}", self.peer_id_string);
        Ok(())
    }

    /// Dial a peer
    pub async fn dial(&mut self, address: &str) -> Result<(), String> {
        if let Some(tx) = &self.command_tx {
            tx.send(NodeCommand::Dial(address.to_string()))
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Send a message to a peer
    pub async fn send_message(&mut self, peer_id: String, envelope: MessageEnvelope) -> Result<(), String> {
        if let Some(tx) = &self.command_tx {
            tx.send(NodeCommand::SendMessage { peer_id, envelope })
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Send raw message bytes (for MessagingManager integration)
    pub async fn send_raw_message(&mut self, peer_id: String, data: Vec<u8>) -> Result<(), String> {
        let envelope = MessageEnvelope::from_bytes(&data)
            .map_err(|e| format!("Failed to parse envelope: {}", e))?;
        self.send_message(peer_id, envelope).await
    }

    /// Stop the P2P node
    pub async fn stop(&mut self) -> Result<(), String> {
        if let Some(tx) = &self.command_tx {
            tx.send(NodeCommand::Stop)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Get connected peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        if let Some(tx) = &self.command_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send(NodeCommand::GetPeers(reply_tx)).await.is_ok() {
                if let Ok(peers) = reply_rx.await {
                    return peers;
                }
            }
        }
        Vec::new()
    }

    /// Get next event from the node
    pub async fn next_event(&mut self) -> Option<NodeEvent> {
        if let Some(rx) = &mut self.event_rx {
            rx.recv().await
        } else {
            None
        }
    }
}

use futures::StreamExt;
