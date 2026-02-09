use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use tracing::{info, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPeer {
    pub peer_id: String,
    pub addresses: Vec<String>,
    pub last_seen: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PeerStore {
    pub peers: HashMap<String, PersistedPeer>,
}

impl PeerStore {
    pub fn load(path: &str) -> Self {
        if !Path::new(path).exists() {
            return Self::default();
        }

        match fs::read_to_string(path) {
            Ok(content) => {
                match serde_json::from_str::<PeerStore>(&content) {
                    Ok(store) => {
                        info!("Loaded {} peers from persistence", store.peers.len());
                        store
                    },
                    Err(_) => {
                        error!("Failed to parse peer store, starting fresh");
                        Self::default()
                    }
                }
            },
            Err(e) => {
                error!("Failed to read peer store at {}: {}", path, e);
                Self::default()
            }
        }
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn update_peer(&mut self, peer_id: String, addresses: Vec<String>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let entry = self.peers.entry(peer_id.clone()).or_insert(PersistedPeer {
            peer_id,
            addresses: Vec::new(),
            last_seen: now,
        });
        
        // Add new addresses without duplicates
        for addr in addresses {
            if !entry.addresses.contains(&addr) {
                entry.addresses.push(addr);
            }
        }
        entry.last_seen = now;
    }
}
