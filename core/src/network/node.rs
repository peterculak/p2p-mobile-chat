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
use libp2p::multiaddr::Protocol;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
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
    /// Reconnect to all bootstrap/relay peers (used after network interface change)
    Reconnect,
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
        let tcp_config = tcp::Config::default().nodelay(true);
        // keepalive not supported on this version of libp2p::tcp::Config

        let upgraded_tcp = match dns::tokio::Transport::system(tcp::tokio::Transport::new(tcp_config.clone())) {
            Ok(dns_tcp) => {
                dns_tcp.upgrade(Version::V1)
                    .authenticate(noise::Config::new(&local_key).map_err(|e| e.to_string())?)
                    .multiplex(yamux::Config::default())
                    .boxed()
            },
            Err(e) => {
                warn!("Failed to create DNS transport: {}. Falling back to plain TCP.", e);
                tcp::tokio::Transport::new(tcp_config)
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
        // CRITICAL: Prioritize relay_transport to handle /p2p-circuit addresses correctly
        let transport = relay_transport
             .or_transport(transport)
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

        // // Listen on configured port (QUIC/UDP)
        // let listen_addr_quic: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", config.listen_port)
        //     .parse()
        //     .map_err(|e: libp2p::multiaddr::Error| e.to_string())?;
        // swarm.listen_on(listen_addr_quic).map_err(|e| e.to_string())?;

        // Reserve on configured relay(s) so other peers can reach us via /p2p-circuit
        for relay_addr in config.bootstrap_peers.iter() {
            if let Ok(multiaddr) = relay_addr.parse::<Multiaddr>() {
                if let Some(listen_addr) = build_relay_listen_addr(&multiaddr) {
                    match swarm.listen_on(listen_addr.clone()) {
                        Ok(_) => info!("Relay: Listening via {listen_addr}"),
                        Err(e) => warn!("Relay: Failed to listen via {listen_addr}: {e}"),
                    }
                }
            }
        }

        // Create channels for communication
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<NodeCommand>(32);
        // BUG FIX 5: Increase event channel capacity to prevent blocking during connection burst
        let (event_tx, event_rx) = mpsc::channel::<NodeEvent>(256);

        self.command_tx = Some(cmd_tx);
        self.event_rx = Some(event_rx);

        let connected_peers = self.connected_peers.clone();
        let is_running = self.is_running.clone();
        let privacy_manager = self.privacy_manager.clone();

        *is_running.write().await = true;

        let persistence_path = self.persistence_path.clone();
        let config_clone = config.clone();
        let relay_listen_addrs: Vec<Multiaddr> = config
            .bootstrap_peers
            .iter()
            .filter_map(|addr| {
                info!("Bootstrap: Parsing address {}", addr);
                addr.parse::<Multiaddr>().ok()
            })
            .filter_map(|addr| {
                let res = build_relay_listen_addr(&addr);
                if let Some(ref l) = res {
                    info!("Relay: Built listen address {}", l);
                } else {
                    warn!("Relay: Failed to build listen address from {}", addr);
                }
                res
            })
            .collect();
        
        tokio::spawn(async move {
            let mut node_swarm = swarm;
            let mut has_relay_listener = false;
            
            // Try enabling relay listening immediately (before dial)
            for listen_addr in relay_listen_addrs.iter() {
                 match node_swarm.listen_on(listen_addr.clone()) {
                     Ok(_) => info!("Relay: Requested reservation via {}", listen_addr),
                     Err(e) => error!("Relay: Failed initial reservation via {}: {}", listen_addr, e),
                 }
            }

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
            let mut relay_reserve_timer = tokio::time::interval(Duration::from_secs(45));
            
            loop {
                tokio::select! {
                    _ = bootstrap_timer.tick() => {
                        let connected_count = node_swarm.connected_peers().count();
                        if connected_count < 2 {
                            info!("Running periodic Kademlia bootstrap (connected to {} peers)...", connected_count);
                            let _ = node_swarm.behaviour_mut().kad.bootstrap();
                        }
                    }
                    _ = relay_reserve_timer.tick() => {
                        if !has_relay_listener && !relay_listen_addrs.is_empty() {
                            for listen_addr in relay_listen_addrs.iter() {
                                match node_swarm.listen_on(listen_addr.clone()) {
                                    Ok(_) => info!("Relay: Re-requesting reservation via {}", listen_addr),
                                    Err(e) => debug!("Relay: Reservation listen failed via {}: {}", listen_addr, e),
                                }
                            }
                        }
                    }
                    event = node_swarm.select_next_some() => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                info!("Network: New listen address - {}", address);
                                if address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                                    has_relay_listener = true;
                                    info!("Relay: Reservation active (listening on p2p-circuit)");
                                }
                                let _ = event_tx.send(NodeEvent::Listening {
                                    address: address.to_string(),
                                }).await;
                            }
                            SwarmEvent::ExpiredListenAddr { address, .. } => {
                                if address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                                    has_relay_listener = false;
                                    warn!("Relay: Reservation expired for {}", address);
                                }
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
                                            // Emit event for UI discovery
                                            let peer_info = PeerInfo {
                                                peer_id: peer.to_string(),
                                                addresses: vec![],
                                            };
                                            let _ = event_tx.send(NodeEvent::PeerDiscovered { peer: peer_info }).await;
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
                                
                                // Filter addresses: Keep only public IPs and Relay circuits for 5G stability
                                let addresses: Vec<String> = info.listen_addrs.iter()
                                    .filter(|a| is_public_or_relay_addr(a))
                                    .map(|a| a.to_string())
                                    .collect();
                                
                                info!("Identify: Filtered down to {} usable addresses for {}", addresses.len(), peer_id);
                                
                                // Update persistence
                                if let Some(path) = &persistence_path {
                                    peer_store.update_peer(peer_id.to_string(), addresses.clone());
                                    let _ = peer_store.save(path);
                                }
                                
                                // Also add to Kademlia so we can find them later
                                for addr_str in &addresses {
                                    if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                                        node_swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                                    }
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
                                
                                // Check if this is our relay
                                let relay_peer_id = "12D3KooWMDgKCqgv6e9oGESb9TYNcUuTWiwEtqWk3tnMWAWkMf3Y";
                                if peer_id.to_string() == relay_peer_id && !has_relay_listener {
                                    info!("Relay: Connected to RELAY! Attempting reservation now...");
                                    for listen_addr in relay_listen_addrs.iter() {
                                         match node_swarm.listen_on(listen_addr.clone()) {
                                             Ok(_) => info!("Relay: Requested reservation via {}", listen_addr),
                                             Err(e) => error!("Relay: Failed reservation via {}: {}", listen_addr, e),
                                         }
                                    }
                                }

                                let _ = event_tx.send(NodeEvent::PeerConnected {
                                    peer_id: peer_id.to_string(),
                                }).await;
                            }
                            SwarmEvent::IncomingConnectionError { error, .. } => {
                                error!("Incoming connection error: {:?}", error);
                            }
                            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                                let error_str = format!("{:?}", error);
                                // No route (65), Network Unreachable (51), Network Down (50), Timeout (60)
                                if error_str.contains("os error 65") || error_str.contains("os error 51") || error_str.contains("os error 50") || error_str.contains("os error 60") {
                                    warn!("Network Interface changed or disconnected (error={}). Re-triggering relay discovery...", error_str);
                                    // RE-DIAL BOOTSTRAP RELAY
                                    let bootstrap_addr = "/ip4/90.250.133.218/tcp/4001/p2p/12D3KooWMDgKCqgv6e9oGESb9TYNcUuTWiwEtqWk3tnMWAWkMf3Y";
                                    if let Ok(maddr) = bootstrap_addr.parse::<Multiaddr>() {
                                        let _ = node_swarm.dial(maddr);
                                    }
                                }

                                match peer_id {
                                    Some(pid) => error!("Outgoing connection error to peer {pid}: {:?}", error),
                                    None => error!("Outgoing connection error to unknown peer: {:?}", error),
                                }
                            }
                            SwarmEvent::ListenerError { listener_id, error } => {
                                error!("Listener Error ID {:?}: {:?}", listener_id, error);
                            }
                            SwarmEvent::ListenerClosed { listener_id, addresses, reason } => {
                                error!("Listener Closed ID {:?}: {:?} Reason: {:?}", listener_id, addresses, reason);
                            }
                            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                                info!("Disconnected from peer: {peer_id}. Cause: {:?}", cause);
                                connected_peers.write().await.remove(&peer_id);
                                let _ = event_tx.send(NodeEvent::PeerDisconnected {
                                    peer_id: peer_id.to_string(),
                                }).await;
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(relay_event)) => {
                                let event_str = format!("{:?}", relay_event);
                                if event_str.contains("Failed") || event_str.contains("Denied") || event_str.contains("Error") {
                                    error!("Relay Client: {}", event_str);
                                } else {
                                    info!("Relay Client: {}", event_str);
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::RelayServer(relay_event)) => {
                                debug!("Relay Server: {:?}", relay_event);
                            }
                            /*
                            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(dcutr_event)) => {
                                info!("DCUTR: {:?}", dcutr_event);
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Autonat(autonat::Event::StatusChanged { old: _, new })) => {
                                info!("AutoNAT: Status changed to {:?}", new);
                                if let autonat::NatStatus::Public(_public_addr) = new {
                                    info!("Organic Mesh: Public IP detected! Acting as a RELAY for friends.");
                                }
                            }
                            */
                            SwarmEvent::Behaviour(BehaviourEvent::Chat(chat_event)) => {
                                match chat_event {
                                    request_response::Event::Message { peer, message } => {
                                        match message {
                                            request_response::Message::Request { request, channel, .. } => {
                                                info!("Received chat request from {peer}");
                                                info!("Chat: Incoming envelope from {peer} (encrypted={}, payload_len={})",
                                                    request.0.encrypted,
                                                    request.0.payload.len()
                                                );
                                                // Send immediate Ack
                                                if let Err(e) = node_swarm.behaviour_mut().chat.send_response(channel, ChatResponse(vec![])) {
                                                    error!("Failed to send Chat Ack: {:?}", e);
                                                }
                                                
                                                let envelope = request.0;
                                                let mut manager = privacy_manager.write().await;
                                                let mut handled_as_onion = false;
                                                
                                                // Parse unencrypted message once for routing decisions
                                                let mut parsed_msg: Option<Message> = None;
                                                if !envelope.encrypted {
                                                    if let Ok(msg) = Message::from_bytes(&envelope.payload) {
                                                        parsed_msg = Some(msg);
                                                    }
                                                }

                                                // Check for Relay Announcement
                                                if let Some(msg) = parsed_msg.as_ref() {
                                                    if msg.message_type == MessageType::RelayAnnouncement {
                                                        if let Ok(pub_key) = hex::decode(&msg.content) {
                                                            if pub_key.len() == 32 {
                                                                let mut key_arr = [0u8; 32];
                                                                key_arr.copy_from_slice(&pub_key);
                                                                manager.register_relay(&peer.to_string(), key_arr);
                                                                info!("Onion: Registered relay {} via announcement", peer);
                                                                info!("Onion: Relay registry count now {}", manager.relay_count());
                                                                
                                                                // Update UI/Events if needed
                                                                let _ = event_tx.send(NodeEvent::PeerDiscovered { 
                                                                    peer: PeerInfo {
                                                                        peer_id: peer.to_string(),
                                                                        addresses: vec![], // Already connected
                                                                    }
                                                                }).await;
                                                                
                                                                // Propagate to app layer (Messaging).
                                                                let _ = event_tx.send(NodeEvent::MessageReceived {
                                                                    peer_id: peer.to_string(),
                                                                    envelope: envelope.clone(),
                                                                }).await;
                                                                handled_as_onion = true;
                                                            }
                                                        }
                                                    }
                                                }

                                                // Check if it's an Onion Packet
                                                if !handled_as_onion {
                                                    if let Some(msg) = parsed_msg.as_ref() {
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
                                                                                     let req_id = node_swarm.behaviour_mut().chat.send_request(&next_peer, ChatRequest(fwd_env));
                                                                                     info!("Onion: Relay send_request to {} -> {:?}", next_peer, req_id);
                                                                                 }
                                                                            }
                                                                            PrivacyEvent::DeliverPayload { next_peer_id, payload } => {
                                                                                if let Ok(next_peer) = next_peer_id.parse::<PeerId>() {
                                                                                    // Exit Node: Forward unwrapped payload to final dest
                                                                                    if let Ok(inner_env) = MessageEnvelope::from_bytes(&payload) {
                                                                                        debug!("Onion: Exit Node delivering to {}", next_peer);
                                                                                        let req_id = node_swarm.behaviour_mut().chat.send_request(&next_peer, ChatRequest(inner_env));
                                                                                        info!("Onion: Exit send_request to {} -> {:?}", next_peer, req_id);
                                                                                    }
                                                                                }
                                                                            }
                                                                            PrivacyEvent::PacketDelivered { payload } => {
                                                                                // Final Destination: It's for US!
                                                                                if let Ok(inner_env) = MessageEnvelope::from_bytes(&payload) {
                                                                                    debug!("Onion: Packet delivered to US!");
                                                                                    info!("Onion: PacketDelivered payload_len={}", payload.len());
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
                            Some(NodeCommand::Reconnect) => {
                                info!("Reconnect: Network interface changed, re-dialing all bootstrap peers...");
                                for relay_addr in config_clone.bootstrap_peers.iter() {
                                    if let Ok(multiaddr) = relay_addr.parse::<Multiaddr>() {
                                        if let Some(peer_id) = multiaddr.iter().find_map(|p| {
                                            if let libp2p::multiaddr::Protocol::P2p(id) = p { Some(id) } else { None }
                                        }) {
                                            node_swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr.clone());
                                        }
                                        match node_swarm.dial(multiaddr.clone()) {
                                            Ok(_) => info!("Reconnect: Re-dialing {}", relay_addr),
                                            Err(e) => warn!("Reconnect: Failed to re-dial {}: {}", relay_addr, e),
                                        }
                                    }
                                }
                            }
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
                                
                                // FORCE DISABLE ONION ROUTING FOR 5G RELAY STABILITY
                                // The cellular relay link cannot handle 8.5KB packets.
                                if false && manager.is_onion_enabled() {
                                    let envelope_bytes = envelope.to_bytes();
                                    if let Some(onion) = manager.wrap_message(&envelope_bytes, &peer_id) {
                                        if let Ok(entry_peer) = onion.entry_peer_id.parse::<PeerId>() {
                                            // ... onion logic ...
                                            debug!("Onion: Routing via {}", entry_peer);
                                            // ...
                                            sent = true;
                                        }
                                    }
                                } else {
                                    warn!("Onion Routing FORCE DISABLED for stability.");
                                }
                                
                                if !sent {
                                    if let Ok(peer) = peer_id.parse::<PeerId>() {
                                        info!("Direct: Sending envelope to {} (encrypted={})", peer, envelope.encrypted);
                                        let req_id = node_swarm.behaviour_mut().chat.send_request(&peer, ChatRequest(envelope));
                                        info!("Direct: send_request to {} -> {:?}", peer, req_id);
                                    } else {
                                        warn!("Invalid peer ID: {}", peer_id);
                                    }
                                }
                            }
                            Some(NodeCommand::Dial(addr)) => {
                                if let Ok(multiaddr) = addr.parse::<Multiaddr>() {
                                    // For p2p-circuit addresses, we MUST register the relay's
                                    // routable address in the peer store BEFORE dialling.
                                    // Otherwise libp2p throws MissingRelayAddr.
                                    // Address format: /ip4/{relay_ip}/tcp/{port}/p2p/{relay_peer}/p2p-circuit/p2p/{dest_peer}
                                    let protocols: Vec<_> = multiaddr.iter().collect();
                                    let has_circuit = protocols.iter().any(|p| matches!(p, Protocol::P2pCircuit));
                                    
                                    if has_circuit {
                                        // Split at P2pCircuit: everything before = relay addr, last P2p = dest peer
                                        let mut relay_addr = Multiaddr::empty();
                                        let mut relay_peer_id: Option<PeerId> = None;
                                        let mut dest_peer_id: Option<PeerId> = None;
                                        let mut past_circuit = false;
                                        
                                        for protocol in &protocols {
                                            if matches!(protocol, Protocol::P2pCircuit) {
                                                past_circuit = true;
                                                // relay_addr is now complete (up to and including relay's /p2p/...)
                                                // extract relay peer from the last P2p before circuit
                                                if let Some(Protocol::P2p(pid)) = relay_addr.iter().last() {
                                                    relay_peer_id = Some(pid);
                                                }
                                                continue;
                                            }
                                            if past_circuit {
                                                if let Protocol::P2p(pid) = protocol {
                                                    dest_peer_id = Some(*pid);
                                                }
                                            } else {
                                                relay_addr.push(protocol.clone());
                                            }
                                        }
                                        
                                        // Register relay's routable address so libp2p can find it
                                        if let Some(relay_pid) = relay_peer_id {
                                            // Strip the /p2p/... suffix to get just the transport addr
                                            let relay_transport_addr: Multiaddr = relay_addr.iter()
                                                .take_while(|p| !matches!(p, Protocol::P2p(_)))
                                                .collect();
                                            info!("Dial: Registering relay {} at {} before circuit dial", relay_pid, relay_transport_addr);
                                            node_swarm.behaviour_mut().kad.add_address(&relay_pid, relay_transport_addr.clone());
                                            // Also ensure the relay is dialled/connected
                                            if !node_swarm.is_connected(&relay_pid) {
                                                let _ = node_swarm.dial(relay_addr.clone());
                                            }
                                        }
                                        
                                        // Register dest peer's circuit address  
                                        if let Some(dest_pid) = dest_peer_id {
                                            info!("Dial: Registering dest peer {} circuit address in Kademlia", dest_pid);
                                            node_swarm.behaviour_mut().kad.add_address(&dest_pid, multiaddr.clone());
                                        }
                                        
                                        info!("Dial: Dialling circuit address {}", multiaddr);
                                        if let Err(e) = node_swarm.dial(multiaddr) {
                                            warn!("Failed to dial circuit address: {e}");
                                        }
                                    } else {
                                        // Non-circuit dial: extract PeerID and add address to Kademlia
                                        if let Some(peer_id) = multiaddr.iter().last().and_then(|p| {
                                            if let Protocol::P2p(peer_id) = p { Some(peer_id) } else { None }
                                        }) {
                                            info!("Dial: Adding address for {} to Kademlia: {}", peer_id, multiaddr);
                                            node_swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr.clone());
                                        }
                                        if let Err(e) = node_swarm.dial(multiaddr) {
                                            warn!("Failed to dial: {e}");
                                        }
                                    }
                                } else {
                                    warn!("Dial: Failed to parse address: {}", addr);
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

    /// Reconnect to all bootstrap/relay peers after a network interface change.
    /// Safe to call while the node is running — does NOT stop/restart the event loop.
    pub async fn reconnect(&mut self) -> Result<(), String> {
        if let Some(tx) = &self.command_tx {
            tx.send(NodeCommand::Reconnect)
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

fn build_relay_listen_addr(addr: &Multiaddr) -> Option<Multiaddr> {
    if addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        return None;
    }

    if !addr.iter().any(|p| matches!(p, Protocol::P2p(_))) {
        return None;
    }

    let mut listen_addr = addr.clone();
    listen_addr.push(Protocol::P2pCircuit);
    Some(listen_addr)
}

fn is_public_or_relay_addr(addr: &Multiaddr) -> bool {
    // Force allow our known relay IP
    if addr.to_string().contains("90.250.133.218") {
        return true;
    }

    if addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        return true;
    }

    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(ip) => {
                let is_pub = is_public_ipv4(ip);
                if !is_pub {
                   debug!("Address Filter: Rejected private IPv4: {}", ip);
                }
                return is_pub;
            },
            Protocol::Ip6(ip) => {
                 let is_pub = is_public_ipv6(ip);
                 if !is_pub {
                    debug!("Address Filter: Rejected private IPv6: {}", ip);
                 }
                 return is_pub;
            },
            _ => {}
        }
    }

    false
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
    {
        return false;
    }

    let octets = ip.octets();
    // 100.64.0.0/10 (shared address space for CGNAT)
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000 {
        return false;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (documentation ranges)
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return false;
    }

    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_unicast_link_local()
        || ip.is_unique_local()
        || ip_is_documentation_v6(ip))
}

fn ip_is_documentation_v6(ip: Ipv6Addr) -> bool {
    // 2001:db8::/32 (documentation range)
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}
