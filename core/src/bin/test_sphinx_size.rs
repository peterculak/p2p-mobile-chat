use sphinx_packet::{
    SphinxPacket,
    route::{Node, NodeAddressBytes, Destination, DestinationAddressBytes},
    header::delays::Delay,
    crypto::PublicKey as SphinxPublicKey,
};
use x25519_dalek::{StaticSecret, PublicKey};
use rand::rngs::OsRng;

pub const PAYLOAD_SIZE: usize = 8192;

fn main() {
    let mut rng = OsRng;
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);
    
    let node = Node::new(
        NodeAddressBytes::from_bytes([0u8; 32]),
        SphinxPublicKey::from(public),
    );
    
    let mut identifier = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rng, &mut identifier);
    let dest = Destination::new(
        DestinationAddressBytes::from_bytes([0u8; 32]),
        identifier,
    );
    
    let mut message = vec![0u8; 4 + PAYLOAD_SIZE];
    message[..4].copy_from_slice(&(PAYLOAD_SIZE as u32).to_be_bytes());
    
    let delays = vec![Delay::new_from_millis(0); 1];
    let packet = SphinxPacket::new(message, &[node], &dest, &delays).unwrap();
    let bytes = packet.to_bytes();
    
    println!("SPHINX_PACKET_SIZE for {} byte payload with 1 hop: {}", PAYLOAD_SIZE, bytes.len());
}
