use std::time::Duration;
use libp2p::{
    identify,
    ping,
    relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    kad,
    request_response::{self, ProtocolSupport},
    PeerId,
};
use tracing::{info, warn, error, debug};
use base64::Engine;

use crate::network::chat::{ChatBehaviour, ChatProtocol, ChatRequest, ChatResponse, ChatEvent};
use crate::privacy::manager::{PrivacyManager, PrivacyConfig, PrivacyEvent};
use crate::messaging::{Message, MessageEnvelope, MessageType};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "RelayNodeBehaviourEvent")]
pub struct RelayNodeBehaviour {
    pub relay: relay::Behaviour,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub chat: ChatBehaviour,
}

pub enum RelayNodeBehaviourEvent {
    Relay(relay::Event),
    Ping(ping::Event),
    Identify(identify::Event),
    Kad(kad::Event),
    Chat(ChatEvent),
}

impl From<relay::Event> for RelayNodeBehaviourEvent {
    fn from(event: relay::Event) -> Self {
        RelayNodeBehaviourEvent::Relay(event)
    }
}

impl From<ping::Event> for RelayNodeBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        RelayNodeBehaviourEvent::Ping(event)
    }
}

impl From<identify::Event> for RelayNodeBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        RelayNodeBehaviourEvent::Identify(event)
    }
}

impl From<kad::Event> for RelayNodeBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        RelayNodeBehaviourEvent::Kad(event)
    }
}

impl From<ChatEvent> for RelayNodeBehaviourEvent {
    fn from(event: ChatEvent) -> Self {
        RelayNodeBehaviourEvent::Chat(event)
    }
}

pub struct RelayNode {
    pub privacy_manager: PrivacyManager,
}

impl RelayNode {
    pub fn new(peer_id: PeerId, public_key: libp2p::identity::PublicKey) -> (Self, RelayNodeBehaviour) {
        let mut privacy_config = PrivacyConfig::default();
        privacy_config.min_hops = 1; 
        privacy_config.relay_enabled = true;
        let privacy_manager = PrivacyManager::new(privacy_config);

        let store = kad::store::MemoryStore::new(peer_id);
        let mut kad_config = kad::Config::default();
        kad_config.set_protocol_names(vec![
            libp2p::StreamProtocol::new("/ipfs/kad/1.0.0"),
        ]);

        let chat = request_response::Behaviour::new(
            vec![(ChatProtocol(), ProtocolSupport::Full)],
            request_response::Config::default(),
        );

        let behaviour = RelayNodeBehaviour {
            relay: relay::Behaviour::new(peer_id, relay::Config::default()),
            ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30))),
            identify: identify::Behaviour::new(identify::Config::new(
                "/securechat/relay/1.0.0".to_string(),
                public_key,
            )),
            kad: kad::Behaviour::with_config(peer_id, store, kad_config),
            chat,
        };

        (Self { privacy_manager }, behaviour)
    }

    pub fn handle_swarm_event(
        &mut self,
        local_peer_id: PeerId,
        behaviour: &mut RelayNodeBehaviour,
        event: SwarmEvent<RelayNodeBehaviourEvent>,
    ) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Relay: Listening on {:?}", address);
            }
            SwarmEvent::Behaviour(RelayNodeBehaviourEvent::Chat(request_response::Event::Message { peer, message })) => {
                if let request_response::Message::Request { request, channel, .. } = message {
                    let envelope = request.0;
                    
                    // Always ACK immediately
                    let _ = behaviour.chat.send_response(channel, ChatResponse(vec![]));

                    if !envelope.encrypted {
                         if let Ok(msg) = Message::from_bytes(&envelope.payload) {
                             if msg.message_type == MessageType::OnionPacket {
                                 if let Ok(packet_bytes) = base64::engine::general_purpose::STANDARD.decode(&msg.content) {
                                     debug!("Onion: Processing packet from {}", peer);
                                     if self.privacy_manager.process_incoming(&packet_bytes) {
                                         // Process generated events
                                         while let Some(event) = self.privacy_manager.next_event() {
                                             match event {
                                                 PrivacyEvent::RelayPacket { next_peer_id, packet_bytes, .. } => {
                                                     if let Ok(next_peer) = next_peer_id.parse::<PeerId>() {
                                                         let fwd_msg = Message::onion_packet(&packet_bytes);
                                                         let fwd_env = MessageEnvelope::unencrypted(
                                                             &local_peer_id.to_string(),
                                                             &fwd_msg
                                                         );
                                                         debug!("Onion: Relaying to {}", next_peer);
                                                         behaviour.chat.send_request(&next_peer, ChatRequest(fwd_env));
                                                     }
                                                 }
                                                 PrivacyEvent::DeliverPayload { next_peer_id, payload } => {
                                                     if let Ok(next_peer) = next_peer_id.parse::<PeerId>() {
                                                         if let Ok(inner_env) = MessageEnvelope::from_bytes(&payload) {
                                                             debug!("Onion: Exit Node delivering to {}", next_peer);
                                                             behaviour.chat.send_request(&next_peer, ChatRequest(inner_env));
                                                         }
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
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Relay: Connected to peer: {:?}", peer_id);
                
                // Send Relay Announcement (Sphinx Public Key)
                let relay_pub_key = hex::encode(self.privacy_manager.relay_public_key());
                let ann_msg = Message::relay_announcement(&relay_pub_key);
                let ann_env = MessageEnvelope::unencrypted(
                    &local_peer_id.to_string(),
                    &ann_msg
                );
                debug!("Sending Relay Announcement to {}", peer_id);
                behaviour.chat.send_request(&peer_id, ChatRequest(ann_env));
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Relay: Disconnected from peer: {:?}", peer_id);
            }
            _ => {}
        }
    }
}
