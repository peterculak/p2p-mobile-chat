//! Network configuration

use std::time::Duration;

/// Configuration for the P2P network node
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Port to listen on (0 for random)
    pub listen_port: u16,
    
    /// Enable mDNS for local peer discovery
    pub enable_mdns: bool,
    
    /// Enable Kademlia DHT for distributed peer discovery
    pub enable_kad: bool,
    
    /// Bootstrap peers for DHT (multiaddrs)
    pub bootstrap_peers: Vec<String>,
    
    /// Idle connection timeout
    pub idle_timeout: Duration,

    /// Enable privacy features (Onion Routing)
    pub enable_onion_routing: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 0, // Random port
            enable_mdns: true,
            enable_kad: true,
            bootstrap_peers: Vec::new(),
            idle_timeout: Duration::from_secs(300),
            enable_onion_routing: false,
        }
    }
}

impl NetworkConfig {
    /// Create config for local testing (mDNS only)
    pub fn local_only() -> Self {
        Self {
            listen_port: 0,
            enable_mdns: true,
            enable_kad: false,
            bootstrap_peers: Vec::new(),
            idle_timeout: Duration::from_secs(300),
            enable_onion_routing: false,
        }
    }

    /// Create config for Private Relay Mesh (Low noise, high privacy)
    pub fn global() -> Self {
        Self {
            listen_port: 0,
            enable_mdns: false, 
            enable_kad: true,
            bootstrap_peers: vec![
                // PRIVATE RELAY CONFIGURATION
                "/ip4/90.250.133.218/tcp/4001/p2p/12D3KooWMDgKCqgv6e9oGESb9TYNcUuTWiwEtqWk3tnMWAWkMf3Y".to_string(),
            ],
            idle_timeout: Duration::from_secs(1800),
            enable_onion_routing: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NetworkConfig::default();
        assert!(config.enable_mdns);
        assert!(config.enable_kad);
        assert_eq!(config.listen_port, 0);
    }

    #[test]
    fn test_local_only_config() {
        let config = NetworkConfig::local_only();
        assert!(config.enable_mdns);
        assert!(!config.enable_kad);
    }
}
