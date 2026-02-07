//! Custom network behaviour combining multiple libp2p protocols

use libp2p::{
    identify, kad, mdns, ping,
    swarm::NetworkBehaviour,
    PeerId,
};
use std::time::Duration;

/// Combined network behaviour for our P2P node
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
pub struct NodeBehaviour {
    /// Kademlia DHT for peer discovery and data storage
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    
    /// mDNS for local network peer discovery
    pub mdns: mdns::tokio::Behaviour,
    
    /// Identify protocol for exchanging peer info
    pub identify: identify::Behaviour,
    
    /// Ping for connection keepalive
    pub ping: ping::Behaviour,
}

/// Events from our combined behaviour
#[derive(Debug)]
pub enum BehaviourEvent {
    Kad(kad::Event),
    Mdns(mdns::Event),
    Identify(identify::Event),
    Ping(ping::Event),
}

impl From<kad::Event> for BehaviourEvent {
    fn from(event: kad::Event) -> Self {
        BehaviourEvent::Kad(event)
    }
}

impl From<mdns::Event> for BehaviourEvent {
    fn from(event: mdns::Event) -> Self {
        BehaviourEvent::Mdns(event)
    }
}

impl From<identify::Event> for BehaviourEvent {
    fn from(event: identify::Event) -> Self {
        BehaviourEvent::Identify(event)
    }
}

impl From<ping::Event> for BehaviourEvent {
    fn from(event: ping::Event) -> Self {
        BehaviourEvent::Ping(event)
    }
}

impl NodeBehaviour {
    /// Create a new behaviour with the given peer ID and keypair
    pub fn new(local_peer_id: PeerId, local_public_key: libp2p::identity::PublicKey) -> Self {
        // Kademlia DHT
        let store = kad::store::MemoryStore::new(local_peer_id);
        let mut kad_config = kad::Config::default();
        kad_config.set_protocol_names(vec![libp2p::StreamProtocol::new("/securechat/kad/1.0.0")]);
        let kad = kad::Behaviour::with_config(local_peer_id, store, kad_config);

        // mDNS for local discovery
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        ).expect("Failed to create mDNS behaviour");

        // Identify protocol
        let identify = identify::Behaviour::new(identify::Config::new(
            "/securechat/id/1.0.0".to_string(),
            local_public_key,
        ));

        // Ping for keepalive
        let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(15)));

        Self {
            kad,
            mdns,
            identify,
            ping,
        }
    }
}
