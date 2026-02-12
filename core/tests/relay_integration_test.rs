use std::time::Duration;
use libp2p::{
    core::{transport::MemoryTransport, upgrade, transport::Transport},
    identity,
    noise,
    relay,
    swarm::SwarmEvent,
    yamux,
    PeerId,
    Multiaddr,
};
use futures::StreamExt;
use securechat_core::network::relay_node::{RelayNode, RelayNodeBehaviour, RelayNodeBehaviourEvent};
use securechat_core::messaging::{Message, MessageEnvelope, MessageType};
use libp2p::request_response;

fn create_swarm(id_keys: identity::Keypair) -> (libp2p::Swarm<RelayNodeBehaviour>, RelayNode) {
    let peer_id = PeerId::from(id_keys.public());
    let transport = MemoryTransport::default()
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&id_keys).unwrap())
        .multiplex(yamux::Config::default())
        .boxed();

    let (relay_node, behaviour) = RelayNode::new(peer_id, id_keys.public());
    
    let swarm = libp2p::Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(30)),
    );

    (swarm, relay_node)
}

#[tokio::test]
async fn test_relay_announcement() {
    let _ = tracing_subscriber::fmt().try_init();
    
    let relay_keys = identity::Keypair::generate_ed25519();
    let client_keys = identity::Keypair::generate_ed25519();
    
    let (mut relay_swarm, mut relay_node) = create_swarm(relay_keys.clone());
    let (mut client_swarm, mut client_node) = create_swarm(client_keys.clone());
    
    let relay_peer_id = *relay_swarm.local_peer_id();
    let relay_addr: Multiaddr = "/memory/1".parse().unwrap();
    
    relay_swarm.listen_on(relay_addr.clone()).unwrap();
    client_swarm.dial(relay_addr).unwrap();
    
    // Drive both swarms
    let mut announcement_received = false;
    
    for _ in 0..20 {
        tokio::select! {
            event = relay_swarm.select_next_some() => {
                relay_node.handle_swarm_event(relay_peer_id, relay_swarm.behaviour_mut(), event);
            }
            event = client_swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(RelayNodeBehaviourEvent::Chat(request_response::Event::Message { message, .. })) = &event {
                    if let request_response::Message::Request { request, .. } = message {
                        let envelope = &request.0;
                        if let Ok(msg) = Message::from_bytes(&envelope.payload) {
                            if msg.message_type == MessageType::RelayAnnouncement {
                                println!("Client received relay announcement: {}", msg.content);
                                announcement_received = true;
                                break;
                            }
                        }
                    }
                }
                client_node.handle_swarm_event(*client_swarm.local_peer_id(), client_swarm.behaviour_mut(), event);
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        if announcement_received { break; }
    }
    
    assert!(announcement_received, "Client should receive RelayAnnouncement on connection");
}

#[tokio::test]
async fn test_onion_forwarding_to_us() {
    let _ = tracing_subscriber::fmt().try_init();
    
    let relay_keys = identity::Keypair::generate_ed25519();
    let (mut relay_swarm, mut relay_node) = create_swarm(relay_keys);
    let relay_peer_id = *relay_swarm.local_peer_id();

    // Fabricate an onion packet for relay_node (acting as destination)
    use securechat_core::privacy::sphinx_wrapper::{create_onion_packet, RelayNode as SphinxRelay, OnionDestination};
    
    let _sphinx_relay = SphinxRelay::new(
        relay_peer_id.to_bytes(),
        relay_node.privacy_manager.relay_public_key()
    );
    
    let dest = OnionDestination::new(relay_node.privacy_manager.relay_public_key().to_vec());
    let payload = b"secret message";
    let packet = create_onion_packet(payload, &[_sphinx_relay], &dest).unwrap();
    
    // Pad to FIXED_PACKET_SIZE (8192)
    let mut padded_packet = vec![0u8; 8192];
    padded_packet[..packet.len()].copy_from_slice(&packet);
    
    let _onion_msg = Message::onion_packet(&padded_packet);
    let _envelope = MessageEnvelope::unencrypted("sender", &_onion_msg);
    
    // Processing should now succeed
    assert!(relay_node.privacy_manager.process_incoming(&padded_packet));
    
    use securechat_core::privacy::manager::PrivacyEvent;
    let mut delivered = false;
    while let Some(event) = relay_node.privacy_manager.next_event() {
        if let PrivacyEvent::PacketDelivered { payload: p } = event {
            assert_eq!(p, payload);
            delivered = true;
        }
    }
    assert!(delivered, "Packet should be delivered if relay is destination");
}

#[tokio::test]
async fn test_exit_node_delivery() {
    let _ = tracing_subscriber::fmt().try_init();
    
    let relay_keys = identity::Keypair::generate_ed25519();
    let (mut relay_swarm, mut relay_node) = create_swarm(relay_keys);
    let relay_peer_id = *relay_swarm.local_peer_id();

    // Fabricate an onion packet where relay is a hop, but NOT destination
    use securechat_core::privacy::sphinx_wrapper::{create_onion_packet, RelayNode as SphinxRelay, OnionDestination};
    
    let sphinx_relay = SphinxRelay::new(
        relay_peer_id.to_bytes(),
        relay_node.privacy_manager.relay_public_key()
    );
    
    let final_dest_keys = identity::Keypair::generate_ed25519();
    let final_dest_peer_id = PeerId::from(final_dest_keys.public());
    let dest_addr = securechat_core::privacy::sphinx_wrapper::peer_id_to_bytes(&final_dest_peer_id.to_string()).unwrap();
    let dest = OnionDestination::new(dest_addr);
    let payload = b"exit payload";
    let packet = create_onion_packet(payload, &[sphinx_relay], &dest).unwrap();
    
    let mut padded_packet = vec![0u8; 8192];
    padded_packet[..packet.len()].copy_from_slice(&packet);
    
    // Process packet
    assert!(relay_node.privacy_manager.process_incoming(&padded_packet));
    
    use securechat_core::privacy::manager::PrivacyEvent;
    let mut exit_forwarded = false;
    while let Some(event) = relay_node.privacy_manager.next_event() {
        if let PrivacyEvent::DeliverPayload { next_peer_id, payload: p } = event {
            assert_eq!(next_peer_id, final_dest_peer_id.to_string());
            assert_eq!(p, payload);
            exit_forwarded = true;
        }
    }
    assert!(exit_forwarded, "Relay should trigger DeliverPayload as Exit Node");
}
