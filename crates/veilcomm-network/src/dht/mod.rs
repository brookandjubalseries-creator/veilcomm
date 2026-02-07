//! Distributed Hash Table for peer discovery
//!
//! Implements a Kademlia-like DHT for:
//! - Peer discovery
//! - Pre-key distribution
//! - Offline message storage

use std::collections::HashMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

// error types available via crate::error if needed

/// Maximum number of pre-key records per key
const MAX_PREKEY_PER_KEY: usize = 5;

/// Maximum number of offline messages per recipient key
const MAX_OFFLINE_MSG_PER_KEY: usize = 50;

/// Maximum total number of records across all keys
const MAX_TOTAL_RECORDS: usize = 10000;

/// Node ID in the DHT (256-bit)
pub type NodeId = [u8; 32];

/// DHT node information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub last_seen: i64,
}

/// DHT record types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtRecord {
    /// Pre-key bundle for a user
    PreKeyBundle(Vec<u8>),
    /// Offline message for a user
    OfflineMessage {
        sender_fingerprint: String,
        recipient_fingerprint: String,
        payload: Vec<u8>,
        timestamp: i64,
        message_id: String,
    },
    /// Node address record
    NodeAddr(SocketAddr),
}

/// Kademlia DHT implementation
pub struct KademliaDht {
    /// Our node ID
    node_id: NodeId,
    /// K-bucket routing table
    buckets: Vec<Vec<NodeInfo>>,
    /// Local storage for DHT records
    storage: HashMap<NodeId, Vec<DhtRecord>>,
    /// K parameter (bucket size)
    k: usize,
}

impl KademliaDht {
    /// Create a new DHT node
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            buckets: vec![Vec::new(); 256],
            storage: HashMap::new(),
            k: 20,
        }
    }

    /// Get our node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Add a node to our routing table
    pub fn add_node(&mut self, node: NodeInfo) {
        // Never add ourselves to the routing table
        if node.id == self.node_id {
            return;
        }

        let bucket_idx = self.bucket_index(&node.id);
        let bucket = &mut self.buckets[bucket_idx];

        // Check if node already exists
        if let Some(pos) = bucket.iter().position(|n| n.id == node.id) {
            // Move to end (most recently seen)
            bucket.remove(pos);
            bucket.push(node);
        } else if bucket.len() < self.k {
            bucket.push(node);
        }
        // If bucket is full and node doesn't exist, we'd ping the oldest
        // For now, just ignore (simplified implementation)
    }

    /// Find the bucket index for a node ID
    fn bucket_index(&self, id: &NodeId) -> usize {
        let distance = xor_distance(&self.node_id, id);
        leading_zeros(&distance).min(255)
    }

    /// Find the k closest nodes to a target ID
    pub fn find_closest(&self, target: &NodeId, count: usize) -> Vec<NodeInfo> {
        let mut all_nodes: Vec<_> = self
            .buckets
            .iter()
            .flatten()
            .cloned()
            .collect();

        all_nodes.sort_by(|a, b| {
            let dist_a = xor_distance(&a.id, target);
            let dist_b = xor_distance(&b.id, target);
            dist_a.cmp(&dist_b)
        });

        all_nodes.truncate(count);
        all_nodes
    }

    /// Store a record locally (with per-type rate limiting)
    pub fn store(&mut self, key: NodeId, record: DhtRecord) {
        // Check total record limit across all keys
        let total: usize = self.storage.values().map(|v| v.len()).sum();
        if total >= MAX_TOTAL_RECORDS {
            tracing::warn!("DHT store refused: total record limit ({}) reached", MAX_TOTAL_RECORDS);
            return;
        }

        let records = self.storage.entry(key).or_default();

        match &record {
            DhtRecord::PreKeyBundle(_) => {
                // Count existing pre-key records for this key
                let prekey_count = records.iter().filter(|r| matches!(r, DhtRecord::PreKeyBundle(_))).count();
                if prekey_count >= MAX_PREKEY_PER_KEY {
                    // Remove the oldest pre-key record
                    if let Some(pos) = records.iter().position(|r| matches!(r, DhtRecord::PreKeyBundle(_))) {
                        records.remove(pos);
                    }
                }
            }
            DhtRecord::OfflineMessage { .. } => {
                // Count existing offline message records for this key
                let msg_count = records.iter().filter(|r| matches!(r, DhtRecord::OfflineMessage { .. })).count();
                if msg_count >= MAX_OFFLINE_MSG_PER_KEY {
                    // Remove the oldest offline message (oldest-first eviction)
                    if let Some(pos) = records.iter().position(|r| matches!(r, DhtRecord::OfflineMessage { .. })) {
                        records.remove(pos);
                    }
                }
            }
            DhtRecord::NodeAddr(_) => {
                // Simple limit: max 10 node addr records per key
                let addr_count = records.iter().filter(|r| matches!(r, DhtRecord::NodeAddr(_))).count();
                if addr_count >= 10 {
                    if let Some(pos) = records.iter().position(|r| matches!(r, DhtRecord::NodeAddr(_))) {
                        records.remove(pos);
                    }
                }
            }
        }

        records.push(record);
    }

    /// Get records for a key
    pub fn get(&self, key: &NodeId) -> Option<&Vec<DhtRecord>> {
        self.storage.get(key)
    }

    /// Remove an offline message by message_id from a specific key.
    /// Returns true if a message was removed.
    pub fn remove_by_id(&mut self, key: &NodeId, message_id: &str) -> bool {
        if let Some(records) = self.storage.get_mut(key) {
            let before = records.len();
            records.retain(|r| {
                if let DhtRecord::OfflineMessage { message_id: mid, .. } = r {
                    mid != message_id
                } else {
                    true
                }
            });
            records.len() < before
        } else {
            false
        }
    }

    /// Purge expired offline messages older than max_age_secs
    pub fn purge_expired(&mut self, max_age_secs: i64) {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - max_age_secs;

        for records in self.storage.values_mut() {
            records.retain(|r| {
                if let DhtRecord::OfflineMessage { timestamp, .. } = r {
                    *timestamp > cutoff
                } else {
                    true
                }
            });
        }

        // Remove empty keys
        self.storage.retain(|_, v| !v.is_empty());
    }

    /// Get offline messages for a recipient
    pub fn get_offline_messages(&self, key: &NodeId) -> Vec<&DhtRecord> {
        if let Some(records) = self.storage.get(key) {
            records.iter().filter(|r| matches!(r, DhtRecord::OfflineMessage { .. })).collect()
        } else {
            vec![]
        }
    }

    /// Number of known nodes
    pub fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }
}

/// Calculate XOR distance between two node IDs
fn xor_distance(a: &NodeId, b: &NodeId) -> NodeId {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Count leading zeros in a node ID
fn leading_zeros(id: &NodeId) -> usize {
    let mut count = 0;
    for byte in id {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_creation() {
        let node_id = [0u8; 32];
        let dht = KademliaDht::new(node_id);
        assert_eq!(dht.node_count(), 0);
    }

    #[test]
    fn test_add_node() {
        let mut dht = KademliaDht::new([0u8; 32]);

        let node = NodeInfo {
            id: [1u8; 32],
            addr: "127.0.0.1:8080".parse().unwrap(),
            last_seen: 0,
        };

        dht.add_node(node);
        assert_eq!(dht.node_count(), 1);
    }

    #[test]
    fn test_find_closest() {
        let mut dht = KademliaDht::new([0u8; 32]);

        for i in 0u16..10 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            dht.add_node(NodeInfo {
                id,
                addr: format!("127.0.0.1:{}", 8000 + i).parse().unwrap(),
                last_seen: 0,
            });
        }

        let target = [5u8; 32];
        let closest = dht.find_closest(&target, 3);
        assert_eq!(closest.len(), 3);
    }

    #[test]
    fn test_store_and_get() {
        let mut dht = KademliaDht::new([0u8; 32]);
        let key = [1u8; 32];

        dht.store(key, DhtRecord::NodeAddr("127.0.0.1:8080".parse().unwrap()));

        let records = dht.get(&key).unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn test_xor_distance() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert_eq!(xor_distance(&a, &b), [0u8; 32]);

        let mut c = [0u8; 32];
        c[0] = 0xff;
        assert_eq!(xor_distance(&a, &c)[0], 0xff);
    }

    #[test]
    fn test_offline_message_store_retrieve() {
        let mut dht = KademliaDht::new([0u8; 32]);
        let key = [1u8; 32];

        dht.store(key, DhtRecord::OfflineMessage {
            sender_fingerprint: "alice".to_string(),
            recipient_fingerprint: "bob".to_string(),
            payload: vec![1, 2, 3],
            timestamp: 1000,
            message_id: "msg-001".to_string(),
        });

        dht.store(key, DhtRecord::OfflineMessage {
            sender_fingerprint: "alice".to_string(),
            recipient_fingerprint: "bob".to_string(),
            payload: vec![4, 5, 6],
            timestamp: 2000,
            message_id: "msg-002".to_string(),
        });

        let msgs = dht.get_offline_messages(&key);
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn test_offline_message_per_key_limit() {
        let mut dht = KademliaDht::new([0u8; 32]);
        let key = [1u8; 32];

        // Store more than the limit
        for i in 0..55 {
            dht.store(key, DhtRecord::OfflineMessage {
                sender_fingerprint: "alice".to_string(),
                recipient_fingerprint: "bob".to_string(),
                payload: vec![i as u8],
                timestamp: i as i64,
                message_id: format!("msg-{:03}", i),
            });
        }

        let msgs = dht.get_offline_messages(&key);
        assert_eq!(msgs.len(), MAX_OFFLINE_MSG_PER_KEY);
    }

    #[test]
    fn test_remove_by_id() {
        let mut dht = KademliaDht::new([0u8; 32]);
        let key = [1u8; 32];

        dht.store(key, DhtRecord::OfflineMessage {
            sender_fingerprint: "alice".to_string(),
            recipient_fingerprint: "bob".to_string(),
            payload: vec![1, 2, 3],
            timestamp: 1000,
            message_id: "msg-001".to_string(),
        });

        dht.store(key, DhtRecord::OfflineMessage {
            sender_fingerprint: "alice".to_string(),
            recipient_fingerprint: "bob".to_string(),
            payload: vec![4, 5, 6],
            timestamp: 2000,
            message_id: "msg-002".to_string(),
        });

        assert!(dht.remove_by_id(&key, "msg-001"));
        assert!(!dht.remove_by_id(&key, "msg-001")); // already removed

        let msgs = dht.get_offline_messages(&key);
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn test_purge_expired() {
        let mut dht = KademliaDht::new([0u8; 32]);
        let key = [1u8; 32];

        let now = chrono::Utc::now().timestamp();

        // Old message (expired)
        dht.store(key, DhtRecord::OfflineMessage {
            sender_fingerprint: "alice".to_string(),
            recipient_fingerprint: "bob".to_string(),
            payload: vec![1],
            timestamp: now - 86400 * 8, // 8 days ago
            message_id: "old".to_string(),
        });

        // Recent message (not expired)
        dht.store(key, DhtRecord::OfflineMessage {
            sender_fingerprint: "alice".to_string(),
            recipient_fingerprint: "bob".to_string(),
            payload: vec![2],
            timestamp: now - 3600, // 1 hour ago
            message_id: "new".to_string(),
        });

        // Purge messages older than 7 days
        dht.purge_expired(86400 * 7);

        let msgs = dht.get_offline_messages(&key);
        assert_eq!(msgs.len(), 1);
        if let DhtRecord::OfflineMessage { message_id, .. } = msgs[0] {
            assert_eq!(message_id, "new");
        }
    }

    #[test]
    fn test_prekey_per_key_limit() {
        let mut dht = KademliaDht::new([0u8; 32]);
        let key = [1u8; 32];

        for i in 0..8 {
            dht.store(key, DhtRecord::PreKeyBundle(vec![i]));
        }

        let records = dht.get(&key).unwrap();
        let prekey_count = records.iter().filter(|r| matches!(r, DhtRecord::PreKeyBundle(_))).count();
        assert_eq!(prekey_count, MAX_PREKEY_PER_KEY);
    }
}
