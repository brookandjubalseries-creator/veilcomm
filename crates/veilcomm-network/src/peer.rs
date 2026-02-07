//! Peer connection management
//!
//! Tracks connected peers, their state, and handles reconnection logic.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::dht::NodeId;

/// State of a peer connection
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Connection in progress
    Connecting,
    /// Performing identity handshake
    Handshaking,
    /// Fully connected and verified
    Connected,
    /// Disconnected
    Disconnected,
}

/// Information about a known peer
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Peer's node ID
    pub node_id: NodeId,
    /// Peer's network address
    pub addr: SocketAddr,
    /// Current connection state
    pub state: PeerState,
    /// Ed25519 identity public key bytes (set after handshake)
    pub identity_public_key: Option<Vec<u8>>,
    /// Last time we heard from this peer (Unix timestamp)
    pub last_seen: i64,
    /// Number of reconnection attempts
    pub reconnect_attempts: u32,
}

impl PeerInfo {
    pub fn new(node_id: NodeId, addr: SocketAddr) -> Self {
        Self {
            node_id,
            addr,
            state: PeerState::Connecting,
            identity_public_key: None,
            last_seen: chrono::Utc::now().timestamp(),
            reconnect_attempts: 0,
        }
    }
}

/// Manages peer connections and their lifecycle
#[derive(Clone)]
pub struct ConnectionManager {
    /// Known peers indexed by node ID
    peers: Arc<RwLock<HashMap<NodeId, PeerInfo>>>,
    /// Reverse lookup: address -> node ID
    addr_to_node: Arc<RwLock<HashMap<SocketAddr, NodeId>>>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            addr_to_node: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new peer (or update existing)
    pub async fn add_peer(&self, info: PeerInfo) {
        let node_id = info.node_id;
        let addr = info.addr;
        self.peers.write().await.insert(node_id, info);
        self.addr_to_node.write().await.insert(addr, node_id);
    }

    /// Update peer state
    pub async fn set_state(&self, node_id: &NodeId, state: PeerState) {
        if let Some(peer) = self.peers.write().await.get_mut(node_id) {
            peer.state = state;
        }
    }

    /// Update peer identity public key after handshake
    pub async fn set_identity_key(&self, node_id: &NodeId, key: Vec<u8>) {
        if let Some(peer) = self.peers.write().await.get_mut(node_id) {
            peer.identity_public_key = Some(key);
        }
    }

    /// Update last_seen timestamp
    pub async fn touch(&self, node_id: &NodeId) {
        if let Some(peer) = self.peers.write().await.get_mut(node_id) {
            peer.last_seen = chrono::Utc::now().timestamp();
        }
    }

    /// Get peer info by node ID
    pub async fn get_peer(&self, node_id: &NodeId) -> Option<PeerInfo> {
        self.peers.read().await.get(node_id).cloned()
    }

    /// Get peer info by address
    pub async fn get_peer_by_addr(&self, addr: &SocketAddr) -> Option<PeerInfo> {
        let node_id = self.addr_to_node.read().await.get(addr).copied()?;
        self.peers.read().await.get(&node_id).cloned()
    }

    /// Get node ID for an address
    pub async fn node_id_for_addr(&self, addr: &SocketAddr) -> Option<NodeId> {
        self.addr_to_node.read().await.get(addr).copied()
    }

    /// Remove a peer
    pub async fn remove_peer(&self, node_id: &NodeId) {
        if let Some(peer) = self.peers.write().await.remove(node_id) {
            self.addr_to_node.write().await.remove(&peer.addr);
        }
    }

    /// Get all connected peers
    pub async fn connected_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .read()
            .await
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .cloned()
            .collect()
    }

    /// Get total peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Calculate exponential backoff delay for reconnection (in seconds)
    pub fn reconnect_delay(attempts: u32) -> u64 {
        let base: u64 = 2;
        let delay = base.saturating_pow(attempts.min(6)); // cap at 64 seconds
        delay.min(64)
    }

    /// Increment reconnect attempts for a peer
    pub async fn increment_reconnect(&self, node_id: &NodeId) -> u32 {
        if let Some(peer) = self.peers.write().await.get_mut(node_id) {
            peer.reconnect_attempts += 1;
            peer.reconnect_attempts
        } else {
            0
        }
    }

    /// Reset reconnect attempts on successful connection
    pub async fn reset_reconnect(&self, node_id: &NodeId) {
        if let Some(peer) = self.peers.write().await.get_mut(node_id) {
            peer.reconnect_attempts = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_manager_add_get() {
        let cm = ConnectionManager::new();
        let node_id = [1u8; 32];
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let info = PeerInfo::new(node_id, addr);
        cm.add_peer(info).await;

        let peer = cm.get_peer(&node_id).await.unwrap();
        assert_eq!(peer.addr, addr);
        assert_eq!(peer.state, PeerState::Connecting);
    }

    #[tokio::test]
    async fn test_state_transitions() {
        let cm = ConnectionManager::new();
        let node_id = [2u8; 32];
        let addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();

        cm.add_peer(PeerInfo::new(node_id, addr)).await;
        cm.set_state(&node_id, PeerState::Connected).await;

        let peer = cm.get_peer(&node_id).await.unwrap();
        assert_eq!(peer.state, PeerState::Connected);

        let connected = cm.connected_peers().await;
        assert_eq!(connected.len(), 1);
    }

    #[test]
    fn test_reconnect_backoff() {
        assert_eq!(ConnectionManager::reconnect_delay(0), 1);
        assert_eq!(ConnectionManager::reconnect_delay(1), 2);
        assert_eq!(ConnectionManager::reconnect_delay(2), 4);
        assert_eq!(ConnectionManager::reconnect_delay(6), 64);
        assert_eq!(ConnectionManager::reconnect_delay(10), 64); // capped
    }
}
