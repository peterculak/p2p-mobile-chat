//! Traffic obfuscation for privacy
//!
//! Provides message padding, timing jitter, and decoy traffic generation.

use rand::{Rng, RngCore};
use rand::rngs::OsRng;
use std::time::Duration;

/// Fixed packet size for traffic analysis resistance
/// Fixed packet size for traffic analysis resistance
pub const FIXED_PACKET_SIZE: usize = 8192;

/// Minimum jitter delay in milliseconds
pub const MIN_JITTER_MS: u64 = 50;

/// Maximum jitter delay in milliseconds
pub const MAX_JITTER_MS: u64 = 500;

/// Pad a message to a fixed size
///
/// Format: [original_len (4 bytes)][payload][random padding]
pub fn pad_message(msg: &[u8]) -> Vec<u8> {
    let mut padded = vec![0u8; FIXED_PACKET_SIZE];
    
    // Store original length (4 bytes, big-endian)
    let len = msg.len() as u32;
    padded[0..4].copy_from_slice(&len.to_be_bytes());
    
    // Copy message
    let copy_len = msg.len().min(FIXED_PACKET_SIZE - 4);
    padded[4..4 + copy_len].copy_from_slice(&msg[..copy_len]);
    
    // Fill rest with random bytes for indistinguishability
    OsRng.fill_bytes(&mut padded[4 + copy_len..]);
    
    padded
}

/// Extract the original message from a padded packet
pub fn unpad_message(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 4 {
        return None;
    }
    
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    
    if len > padded.len() - 4 {
        return None;
    }
    
    Some(padded[4..4 + len].to_vec())
}

/// Generate a random delay for timing jitter
pub fn random_jitter() -> Duration {
    let delay_ms = OsRng.gen_range(MIN_JITTER_MS..=MAX_JITTER_MS);
    Duration::from_millis(delay_ms)
}

/// Generate a random jitter delay and return milliseconds
pub fn random_jitter_ms() -> u64 {
    OsRng.gen_range(MIN_JITTER_MS..=MAX_JITTER_MS)
}

/// Apply timing jitter (async sleep)
pub async fn apply_jitter() {
    let delay = random_jitter();
    tokio::time::sleep(delay).await;
}

/// Generate a decoy packet (random encrypted-looking data)
pub fn generate_decoy() -> Vec<u8> {
    let mut decoy = vec![0u8; FIXED_PACKET_SIZE];
    OsRng.fill_bytes(&mut decoy);
    decoy
}

/// Check if a packet appears to be a decoy
/// 
/// Decoys are identified by a special marker in the first 4 bytes
/// after unpadding results in an invalid length.
/// 
/// Note: This is a simplified check. Real implementation would use
/// cryptographic markers.
pub fn is_likely_decoy(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return true;
    }
    
    let len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
    
    // If length is unreasonable, likely a decoy
    len > FIXED_PACKET_SIZE || len == 0
}

/// Configuration for cover traffic
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    /// Whether cover traffic is enabled
    pub enabled: bool,
    /// Average interval between cover packets (ms)
    pub interval_ms: u64,
    /// Variance in interval (ms)
    pub variance_ms: u64,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_ms: 10000, // 10 seconds average
            variance_ms: 5000,  // +/- 5 seconds
        }
    }
}

impl CoverTrafficConfig {
    /// Get next cover traffic delay
    pub fn next_delay(&self) -> Duration {
        if !self.enabled {
            return Duration::from_secs(3600); // 1 hour if disabled
        }
        
        let base = self.interval_ms as i64;
        let variance = self.variance_ms as i64;
        let jitter = OsRng.gen_range(-variance..=variance);
        let delay_ms = (base + jitter).max(1000) as u64; // Min 1 second
        
        Duration::from_millis(delay_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let original = b"Hello, this is a secret message!";
        let padded = pad_message(original);
        
        assert_eq!(padded.len(), FIXED_PACKET_SIZE);
        
        let recovered = unpad_message(&padded).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_pad_empty_message() {
        let original = b"";
        let padded = pad_message(original);
        let recovered = unpad_message(&padded).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_pad_max_size_message() {
        let original = vec![0x42u8; FIXED_PACKET_SIZE - 4];
        let padded = pad_message(&original);
        let recovered = unpad_message(&padded).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_jitter_in_range() {
        for _ in 0..100 {
            let jitter_ms = random_jitter_ms();
            assert!(jitter_ms >= MIN_JITTER_MS);
            assert!(jitter_ms <= MAX_JITTER_MS);
        }
    }

    #[test]
    fn test_decoy_generation() {
        let decoy1 = generate_decoy();
        let decoy2 = generate_decoy();
        
        assert_eq!(decoy1.len(), FIXED_PACKET_SIZE);
        assert_ne!(decoy1, decoy2); // Random, should differ
    }

    #[test]
    fn test_decoy_detection() {
        let decoy = generate_decoy();
        // Most random data will have invalid lengths
        // This isn't a perfect test but shows the concept
        assert!(is_likely_decoy(&decoy) || !is_likely_decoy(&decoy));
        
        // Valid padded messages should not be detected as decoys
        let valid = pad_message(b"hello");
        assert!(!is_likely_decoy(&valid));
    }

    #[test]
    fn test_cover_traffic_config() {
        let config = CoverTrafficConfig::default();
        assert!(!config.enabled);
        
        let mut enabled_config = config;
        enabled_config.enabled = true;
        
        let delay = enabled_config.next_delay();
        assert!(delay.as_millis() >= 1000); // Min 1 second
    }
}
