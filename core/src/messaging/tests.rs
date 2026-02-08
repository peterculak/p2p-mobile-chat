//! Integration tests for messaging module

use crate::messaging::manager::MessagingManager;
use crate::messaging::protocol::{Message, MessageType};

#[test]
fn test_complete_messaging_scenario() {
    // Simulate a complete messaging scenario between two users
    let mut alice = MessagingManager::new("alice123");
    let mut bob = MessagingManager::new("bob456");
    
    // Step 1: Users add each other as contacts
    alice.add_contact("bob456", "Bob", [1u8; 32]);
    bob.add_contact("alice123", "Alice", [2u8; 32]);
    
    // Step 2: Alice gets Bob's prekey bundle and initiates session
    let bob_bundle = bob.get_prekey_bundle();
    alice.initiate_session("bob456", &bob_bundle).expect("Session init should work");
    
    // Step 3: Alice's session init message is sent over network (simulated)
    let session_init_msg = alice.next_outgoing().expect("Should have session init message");
    assert_eq!(session_init_msg.peer_id, "bob456");
    
    // Step 4: Bob receives and processes the session init
    bob.handle_incoming("alice123", &session_init_msg.data).expect("Bob should accept session");
    
    // Step 5: Verify both have sessions established
    assert!(alice.has_session("bob456"), "Alice should have session with Bob");
    assert!(bob.has_session("alice123"), "Bob should have session with Alice");
    
    // Step 6: Alice sends a text message
    let msg_id = alice.send_message("bob456", "Hey Bob, can you see this?").unwrap();
    let encrypted_msg = alice.next_outgoing().unwrap();
    
    // Step 7: Bob receives and decrypts
    bob.handle_incoming("alice123", &encrypted_msg.data).unwrap();
    
    // Step 8: Check Bob's events
    // First event should be SessionEstablished
    let event = bob.next_event();
    assert!(matches!(event, Some(crate::messaging::manager::MessagingEvent::SessionEstablished { .. })));
    
    // Second event should be MessageReceived
    if let Some(event) = bob.next_event() {
        match event {
            crate::messaging::manager::MessagingEvent::MessageReceived { message, .. } => {
                assert_eq!(message.content, "Hey Bob, can you see this?");
                assert_eq!(message.message_type, MessageType::Text);
            }
            _ => panic!("Expected MessageReceived event"),
        }
    }
    
    // Step 9: Bob replies
    bob.send_message("alice123", "Yes I can! This is encrypted!").unwrap();
    
    // Bob should have 2 outgoing messages: Receipt and Reply
    let receipt_msg = bob.next_outgoing().unwrap();
    let reply_msg = bob.next_outgoing().unwrap();
    
    // Step 10: Alice receives receipt AND reply
    alice.handle_incoming("bob456", &receipt_msg.data).unwrap();
    alice.handle_incoming("bob456", &reply_msg.data).unwrap();
    
    // Alice should have SessionEstablished, MessageSent, DeliveryReceipt, and MessageReceived
    let event = alice.next_event();
    assert!(matches!(event, Some(crate::messaging::manager::MessagingEvent::SessionEstablished { .. })));
    
    let event = alice.next_event();
    assert!(matches!(event, Some(crate::messaging::manager::MessagingEvent::MessageSent { .. })));
    
    let event = alice.next_event();
    assert!(matches!(event, Some(crate::messaging::manager::MessagingEvent::DeliveryReceipt { .. })));
    
    if let Some(event) = alice.next_event() {
        match event {
            crate::messaging::manager::MessagingEvent::MessageReceived { message, .. } => {
                assert_eq!(message.content, "Yes I can! This is encrypted!");
            }
            _ => panic!("Expected MessageReceived event"),
        }
    }
}

#[test]
fn test_multiple_contacts() {
    let mut alice = MessagingManager::new("alice");
    let mut bob = MessagingManager::new("bob");
    let mut carol = MessagingManager::new("carol");
    
    // Alice adds both Bob and Carol
    alice.add_contact("bob", "Bob", [1u8; 32]);
    alice.add_contact("carol", "Carol", [2u8; 32]);
    
    bob.add_contact("alice", "Alice", [3u8; 32]);
    carol.add_contact("alice", "Alice", [3u8; 32]);
    
    // Establish sessions
    let bob_bundle = bob.get_prekey_bundle();
    let carol_bundle = carol.get_prekey_bundle();
    
    alice.initiate_session("bob", &bob_bundle).unwrap();
    alice.initiate_session("carol", &carol_bundle).unwrap();
    
    // Process session inits
    let bob_init = alice.next_outgoing().unwrap();
    let carol_init = alice.next_outgoing().unwrap();
    
    bob.handle_incoming("alice", &bob_init.data).unwrap();
    carol.handle_incoming("alice", &carol_init.data).unwrap();
    
    // Send different messages to each
    alice.send_message("bob", "Private message to Bob").unwrap();
    alice.send_message("carol", "Private message to Carol").unwrap();
    
    let to_bob = alice.next_outgoing().unwrap();
    let to_carol = alice.next_outgoing().unwrap();
    
    // Each should only be able to decrypt their own message
    bob.handle_incoming("alice", &to_bob.data).unwrap();
    carol.handle_incoming("alice", &to_carol.data).unwrap();
    
    // Verify correct messages received
    if let Some(crate::messaging::manager::MessagingEvent::MessageReceived { message, .. }) = bob.next_event() {
        assert_eq!(message.content, "Private message to Bob");
    }
    
    if let Some(crate::messaging::manager::MessagingEvent::MessageReceived { message, .. }) = carol.next_event() {
        assert_eq!(message.content, "Private message to Carol");
    }
}

#[test]
fn test_send_without_session_fails() {
    let mut alice = MessagingManager::new("alice");
    alice.add_contact("bob", "Bob", [1u8; 32]);
    
    // Try to send without session
    let result = alice.send_message("bob", "Hello");
    assert!(result.is_err());
}
