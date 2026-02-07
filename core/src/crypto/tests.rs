//! Integration tests for the crypto module

use crate::crypto::keys::{IdentityKeyPair, SignedPreKey, OneTimePreKey, PreKeyBundle};
use crate::crypto::session::Session;

#[test]
fn test_full_protocol_flow() {
    // Complete Signal Protocol flow test
    
    // Step 1: Both parties generate identities
    let alice_identity = IdentityKeyPair::generate();
    let bob_identity = IdentityKeyPair::generate();
    
    // Step 2: Bob generates and publishes prekeys
    let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity);
    let bob_otpk1 = OneTimePreKey::generate(1);
    let bob_otpk2 = OneTimePreKey::generate(2);
    
    // Step 3: Bob publishes his bundle
    let bob_bundle = PreKeyBundle::new(
        &bob_identity,
        &bob_signed_prekey,
        Some(&bob_otpk1),
    );
    
    // Step 4: Alice initiates session using Bob's bundle
    let (mut alice_session, initial_msg) = Session::initiate(
        alice_identity.clone(),
        &bob_bundle,
    ).expect("Alice should initiate session");
    
    // Verify one-time prekey was used
    assert_eq!(initial_msg.used_one_time_prekey_id, Some(1));
    
    // Step 5: Bob receives initial message and establishes session
    let mut bob_session = Session::respond(
        bob_identity.clone(),
        &bob_signed_prekey,
        Some(&bob_otpk1),
        &initial_msg,
    ).expect("Bob should respond to session");
    
    // Step 6: Test conversation
    let messages = vec![
        ("Alice", "Hey Bob, this is a secure message!"),
        ("Bob", "Hi Alice! I got your message."),
        ("Alice", "Great! Forward secrecy is working."),
        ("Bob", "Each message uses a new key."),
        ("Alice", "Even if someone compromises our keys..."),
        ("Bob", "They can't read past messages."),
    ];
    
    for (sender, text) in messages {
        if sender == "Alice" {
            let encrypted = alice_session.encrypt(text.as_bytes())
                .expect("Alice should encrypt");
            let decrypted = bob_session.decrypt(&encrypted)
                .expect("Bob should decrypt");
            assert_eq!(text.as_bytes(), decrypted.as_slice());
        } else {
            let encrypted = bob_session.encrypt(text.as_bytes())
                .expect("Bob should encrypt");
            let decrypted = alice_session.decrypt(&encrypted)
                .expect("Alice should decrypt");
            assert_eq!(text.as_bytes(), decrypted.as_slice());
        }
    }
}

#[test]
fn test_multiple_sessions_same_identity() {
    // Test that one identity can have multiple sessions
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let carol = IdentityKeyPair::generate();
    
    // Bob's prekeys
    let bob_spk = SignedPreKey::generate(1, &bob);
    let bob_bundle = PreKeyBundle::new(&bob, &bob_spk, None);
    
    // Carol's prekeys
    let carol_spk = SignedPreKey::generate(1, &carol);
    let carol_bundle = PreKeyBundle::new(&carol, &carol_spk, None);
    
    // Alice creates sessions with both
    let (mut alice_bob, alice_bob_init) = Session::initiate(alice.clone(), &bob_bundle).unwrap();
    let (mut alice_carol, alice_carol_init) = Session::initiate(alice.clone(), &carol_bundle).unwrap();
    
    let mut bob_session = Session::respond(bob, &bob_spk, None, &alice_bob_init).unwrap();
    let mut carol_session = Session::respond(carol, &carol_spk, None, &alice_carol_init).unwrap();
    
    // Messages to Bob
    let enc = alice_bob.encrypt(b"Hello Bob").unwrap();
    assert_eq!(bob_session.decrypt(&enc).unwrap(), b"Hello Bob");
    
    // Messages to Carol
    let enc = alice_carol.encrypt(b"Hello Carol").unwrap();
    assert_eq!(carol_session.decrypt(&enc).unwrap(), b"Hello Carol");
}

#[test]
fn test_one_time_prekey_consumed() {
    // Verify one-time prekeys are properly tracked
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    
    let bob_spk = SignedPreKey::generate(1, &bob);
    let bob_otpk = OneTimePreKey::generate(42);
    
    let bundle = PreKeyBundle::new(&bob, &bob_spk, Some(&bob_otpk));
    
    let (_, init) = Session::initiate(alice, &bundle).unwrap();
    
    // The used prekey ID should be reported
    assert_eq!(init.used_one_time_prekey_id, Some(42));
}

#[test]
fn test_large_message_encryption() {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let bob_spk = SignedPreKey::generate(1, &bob);
    let bundle = PreKeyBundle::new(&bob, &bob_spk, None);
    
    let (mut alice_session, init) = Session::initiate(alice, &bundle).unwrap();
    let mut bob_session = Session::respond(bob, &bob_spk, None, &init).unwrap();
    
    // Large message (1MB)
    let large_msg = vec![0x42u8; 1024 * 1024];
    let encrypted = alice_session.encrypt(&large_msg).unwrap();
    let decrypted = bob_session.decrypt(&encrypted).unwrap();
    
    assert_eq!(large_msg, decrypted);
}

#[test]
fn test_empty_message_encryption() {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let bob_spk = SignedPreKey::generate(1, &bob);
    let bundle = PreKeyBundle::new(&bob, &bob_spk, None);
    
    let (mut alice_session, init) = Session::initiate(alice, &bundle).unwrap();
    let mut bob_session = Session::respond(bob, &bob_spk, None, &init).unwrap();
    
    // Empty message
    let encrypted = alice_session.encrypt(&[]).unwrap();
    let decrypted = bob_session.decrypt(&encrypted).unwrap();
    
    assert!(decrypted.is_empty());
}
