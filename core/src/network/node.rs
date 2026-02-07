//! P2P Node implementation

use crate::network::behaviour::{NodeBehaviour, BehaviourEvent};
use crate::network::config::NetworkConfig;

use libp2p::{
    core::transport::upgrade::Version,
    identity,
    noise,
    swarm::{SwarmEvent, Swarm},
    tcp, yamux, Multiaddr, PeerId, Transport,
};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, oneshot};
use tracing::{info, warn, debug, error};

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
    /// Error occurred
    Error { message: String },
}

/// Commands that can be sent to the node
enum NodeCommand {
    /// Stop the node
    Stop,
    /// Get connected peers
    GetPeers(oneshot::Sender<Vec<PeerInfo>>),
    /// Dial a peer
    Dial(String),
}

/// A P2P network node
pub struct P2PNode {
    /// Our peer ID
    local_peer_id: PeerId,
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
}

impl P2PNode {
    /// Create a new P2P node with the given configuration
    pub fn new(_config: NetworkConfig) -> Self {
        // Generate a new identity (in production, we'd use stored keys)
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        Self {
            local_peer_id,
            peer_id_string: local_peer_id.to_string(),
            command_tx: None,
            event_rx: None,
            connected_peers: Arc::new(RwLock::new(HashSet::new())),
            is_running: Arc::new(RwLock::new(false)),
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
            return Err("Node is already running".to_string());
        }

        // Generate identity
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        self.local_peer_id = local_peer_id;
        self.peer_id_string = local_peer_id.to_string();

        // Create transport
        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(Version::V1Lazy)
            .authenticate(noise::Config::new(&local_key).map_err(|e| e.to_string())?)
            .multiplex(yamux::Config::default())
            .boxed();

        // Create behaviour
        let behaviour = NodeBehaviour::new(local_peer_id, local_key.public());

        // Create swarm
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );

        // Listen on configured port
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", config.listen_port)
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| e.to_string())?;
        
        swarm.listen_on(listen_addr).map_err(|e| e.to_string())?;

        // Create channels for communication
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<NodeCommand>(32);
        let (event_tx, event_rx) = mpsc::channel::<NodeEvent>(64);

        self.command_tx = Some(cmd_tx);
        self.event_rx = Some(event_rx);

        let connected_peers = self.connected_peers.clone();
        let is_running = self.is_running.clone();

        *is_running.write().await = true;

        // Spawn the event loop
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Handle swarm events
                    event = swarm.select_next_some() => {
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
                                            swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                            connected_peers.write().await.insert(peer_id);
                                            let _ = event_tx.send(NodeEvent::PeerDiscovered {
                                                peer: PeerInfo {
                                                    peer_id: peer_id.to_string(),
                                                    addresses: vec![addr.to_string()],
                                                },
                                            }).await;
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
                                debug!("Kademlia event: {:?}", kad_event);
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Ping(ping_event)) => {
                                debug!("Ping: {:?}", ping_event);
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                info!("Connected to peer: {peer_id}");
                                connected_peers.write().await.insert(peer_id);
                            }
                            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                info!("Disconnected from peer: {peer_id}");
                                connected_peers.write().await.remove(&peer_id);
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
                            Some(NodeCommand::Dial(addr)) => {
                                if let Ok(multiaddr) = addr.parse::<Multiaddr>() {
                                    if let Err(e) = swarm.dial(multiaddr) {
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
