use std::error::Error;
use std::time::Duration;
use libp2p::{
    core::{upgrade, muxing::StreamMuxerBox},
    identify,
    identity,
    noise,
    ping,
    relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp,
    quic,
    yamux,
    PeerId,
    Multiaddr,
    multiaddr::Protocol,
    Transport,
    SwarmBuilder,
    kad,
    request_response::{self, ProtocolSupport},
};
use tracing::{info, warn, error, debug};
use tracing_subscriber::EnvFilter;
use futures::future::Either;
use futures::stream::StreamExt;
use base64::Engine;

use securechat_core::network::relay_node::{RelayNode, RelayNodeBehaviour, RelayNodeBehaviourEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .try_init();

    // Check for existing identity file
    let id_file = "relay_identity.key";
    let id_keys = if let Ok(bytes) = std::fs::read(id_file) {
        identity::Keypair::from_protobuf_encoding(&bytes)?
    } else {
        info!("Generating new Relay Identity Keypair...");
        let keys = identity::Keypair::generate_ed25519();
        if let Ok(bytes) = keys.to_protobuf_encoding() {
            let _ = std::fs::write(id_file, bytes);
        }
        keys
    };

    let peer_id = PeerId::from(id_keys.public());
    info!("Relay Server starting (or re-starting) with PeerID: {}", peer_id);

    // Create TCP Transport
    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&id_keys)?)
        .multiplex(yamux::Config::default())
        .boxed();

    // Create QUIC Transport
    let quic_transport = quic::tokio::Transport::new(quic::Config::new(&id_keys));

    // Combine Transports
    let transport = tcp_transport
        .or_transport(quic_transport)
        .map(|either, _| match either {
            Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
        })
        .boxed();

    // Initialize Relay Node logic and behaviour
    let (mut relay_node, behaviour) = RelayNode::new(peer_id, id_keys.public());

    // Create Swarm
    let mut swarm = libp2p::Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(1800)),
    );

    // Listen on all interfaces
    // TCP
    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;
    // QUIC (UDP)
    swarm.listen_on("/ip4/0.0.0.0/udp/4001/quic-v1".parse()?)?;

    // Announce External Address (Public IP) to ensure circuits form correctly
    let public_addr_tcp: Multiaddr = "/ip4/90.250.133.218/tcp/4001".parse()?;
    let public_addr_quic: Multiaddr = "/ip4/90.250.133.218/udp/4001/quic-v1".parse()?;
    swarm.add_external_address(public_addr_tcp);
    swarm.add_external_address(public_addr_quic);

    info!("Listening on TCP/UDP port 4001...");

    loop {
        let event = swarm.select_next_some().await;

        if let SwarmEvent::ConnectionEstablished { peer_id: remote, .. } = &event {
            let circuit_addr = build_relay_circuit_addr(peer_id, *remote);
            swarm.add_peer_address(*remote, circuit_addr);
            info!("Relay: Added circuit address for peer {}", remote);
        }

        relay_node.handle_swarm_event(peer_id, swarm.behaviour_mut(), event);
    }
}

fn build_relay_circuit_addr(local_peer_id: PeerId, dst_peer_id: PeerId) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::P2p(local_peer_id.into()));
    addr.push(Protocol::P2pCircuit);
    addr.push(Protocol::P2p(dst_peer_id.into()));
    addr
}
