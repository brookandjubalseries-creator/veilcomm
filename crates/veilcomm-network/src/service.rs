//! Network service - ties transport, DHT, and connection management together
//!
//! This is the main entry point for networking in VeilComm.

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use tokio::sync::{mpsc, RwLock};

use crate::dht::{DhtRecord, KademliaDht, NodeId, NodeInfo};
use crate::error::{Error, Result};
use crate::peer::{ConnectionManager, PeerInfo, PeerState};
use crate::protocol::{NodeEntry, WireMessage};
use crate::transport::quic::{
    read_length_prefixed, write_length_prefixed, QuicConfig, QuicTransport,
};

/// Events emitted by the network service to the application layer
#[derive(Clone, Debug)]
pub enum NetworkEvent {
    /// A new peer has connected and completed handshake
    PeerConnected {
        node_id: NodeId,
        addr: SocketAddr,
    },
    /// A peer has disconnected
    PeerDisconnected {
        node_id: NodeId,
    },
    /// An encrypted message was received from a peer
    MessageReceived {
        sender_id: String,
        recipient_id: String,
        payload: Vec<u8>,
    },
    /// A pre-key bundle was received (response to a request)
    PreKeyBundleReceived {
        fingerprint: String,
        bundle_data: Vec<u8>,
    },
    /// A DHT lookup completed
    DhtLookupComplete {
        key: NodeId,
        values: Vec<Vec<u8>>,
    },
}

/// Configuration for the network service
pub struct NetworkServiceConfig {
    /// QUIC transport configuration
    pub quic_config: QuicConfig,
    /// Our Ed25519 signing key (for handshake authentication)
    pub signing_key: SigningKey,
    /// Our node ID
    pub node_id: NodeId,
}

/// The main network service
pub struct NetworkService {
    /// QUIC transport
    transport: QuicTransport,
    /// DHT for peer/record discovery
    dht: Arc<RwLock<KademliaDht>>,
    /// Connection manager
    connections: ConnectionManager,
    /// Our node ID
    node_id: NodeId,
    /// Our Ed25519 signing key
    signing_key: SigningKey,
    /// Event sender for the application layer
    event_tx: mpsc::UnboundedSender<NetworkEvent>,
    /// Event receiver (taken by the app)
    event_rx: Option<mpsc::UnboundedReceiver<NetworkEvent>>,
}

impl NetworkService {
    /// Create a new network service
    pub fn new(config: NetworkServiceConfig) -> Result<Self> {
        let transport = QuicTransport::new(config.quic_config)?;
        let dht = Arc::new(RwLock::new(KademliaDht::new(config.node_id)));
        let connections = ConnectionManager::new();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Ok(Self {
            transport,
            dht,
            connections,
            node_id: config.node_id,
            signing_key: config.signing_key,
            event_tx,
            event_rx: Some(event_rx),
        })
    }

    /// Take the event receiver (can only be called once)
    pub fn take_event_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<NetworkEvent>> {
        self.event_rx.take()
    }

    /// Start the network service (bind QUIC endpoint)
    pub async fn start(&mut self) -> Result<()> {
        self.transport.start().await?;
        tracing::info!("Network service started, node_id: {}", hex::encode(self.node_id));
        Ok(())
    }

    /// Get our local listening address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.transport.local_addr()
    }

    /// Connect to a peer and perform handshake
    pub async fn connect_to_peer(&self, addr: SocketAddr) -> Result<NodeId> {
        // QUIC connect
        let conn = self.transport.connect(addr).await?;

        // Register peer as connecting
        let temp_node_id = [0u8; 32]; // placeholder until handshake
        let mut info = PeerInfo::new(temp_node_id, addr);
        info.state = PeerState::Handshaking;
        self.connections.add_peer(info).await;

        // Perform handshake
        let peer_node_id = self.perform_handshake_initiator(&conn, addr).await?;

        // Update peer info with real node_id
        self.connections.remove_peer(&temp_node_id).await;
        let mut peer_info = PeerInfo::new(peer_node_id, addr);
        peer_info.state = PeerState::Connected;
        self.connections.add_peer(peer_info).await;
        self.connections.reset_reconnect(&peer_node_id).await;

        // Add to DHT routing table
        self.dht.write().await.add_node(NodeInfo {
            id: peer_node_id,
            addr,
            last_seen: chrono::Utc::now().timestamp(),
        });

        // Emit event
        let _ = self.event_tx.send(NetworkEvent::PeerConnected {
            node_id: peer_node_id,
            addr,
        });

        tracing::info!(
            "Peer connected: {} at {}",
            hex::encode(peer_node_id),
            addr
        );

        Ok(peer_node_id)
    }

    /// Perform handshake as initiator (we connected to them)
    async fn perform_handshake_initiator(
        &self,
        conn: &quinn::Connection,
        addr: SocketAddr,
    ) -> Result<NodeId> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Handshake(format!("Failed to open stream: {}", e)))?;

        // Generate a random nonce for the challenge
        let nonce: [u8; 32] = rand::random();

        // Build challenge: our node_id + peer addr bytes + nonce
        let challenge = build_handshake_challenge(&self.node_id, &addr, &nonce);

        // Send our handshake
        let listen_addr = self.transport.local_addr().unwrap_or(addr);
        let handshake = WireMessage::Handshake {
            node_id: self.node_id,
            identity_public_key: self.signing_key.verifying_key().as_bytes().to_vec(),
            signature: self.signing_key.sign(&challenge).to_bytes().to_vec(),
            nonce: nonce.to_vec(),
            listen_addr,
        };

        let data = handshake
            .to_bytes()
            .map_err(Error::Serialization)?;
        write_length_prefixed(&mut send, &data).await?;
        let _ = send.finish();

        // Read their handshake ack
        let response_data = read_length_prefixed(&mut recv).await?;
        let response = WireMessage::from_bytes(&response_data)
            .map_err(Error::Serialization)?;

        match response {
            WireMessage::HandshakeAck {
                node_id,
                identity_public_key,
                signature,
                nonce: ack_nonce,
                listen_addr: _peer_listen_addr,
            } => {
                // Rebuild the challenge from the ack's nonce and verify signature
                let ack_challenge = build_handshake_challenge(&node_id, &addr, &ack_nonce);
                self.verify_handshake_signature(&identity_public_key, &signature, &ack_challenge)?;
                self.connections.set_identity_key(&node_id, identity_public_key).await;
                Ok(node_id)
            }
            WireMessage::Error { message, .. } => {
                Err(Error::Handshake(format!("Peer rejected: {}", message)))
            }
            _ => Err(Error::Handshake("Unexpected response".to_string())),
        }
    }

    /// Verify a handshake signature against the provided challenge bytes
    fn verify_handshake_signature(&self, public_key_bytes: &[u8], signature_bytes: &[u8], challenge: &[u8]) -> Result<()> {
        if public_key_bytes.len() != 32 {
            return Err(Error::Handshake("Invalid public key length".to_string()));
        }
        if signature_bytes.len() != 64 {
            return Err(Error::Handshake("Invalid signature length".to_string()));
        }

        let key_bytes: [u8; 32] = public_key_bytes.try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| Error::Handshake(format!("Invalid public key: {}", e)))?;

        let sig_bytes: [u8; 64] = signature_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(challenge, &signature)
            .map_err(|_| Error::Handshake("Invalid handshake signature".to_string()))?;

        Ok(())
    }

    /// Handle an incoming connection (called from accept loop)
    pub async fn handle_incoming_connection(
        &self,
        conn: quinn::Connection,
        remote_addr: SocketAddr,
    ) {
        let event_tx = self.event_tx.clone();
        let dht = self.dht.clone();
        let connections = self.connections.clone();
        let node_id = self.node_id;
        let signing_key = self.signing_key.clone();

        let signing_key_bytes = signing_key.to_bytes();
        tokio::spawn(async move {
            // Handle bidirectional streams from this connection
            loop {
                match conn.accept_bi().await {
                    Ok((mut send, mut recv)) => {
                        let event_tx = event_tx.clone();
                        let dht = dht.clone();
                        let connections = connections.clone();
                        let sk = SigningKey::from_bytes(&signing_key_bytes);

                        tokio::spawn(async move {
                            if let Ok(data) = read_length_prefixed(&mut recv).await {
                                if let Ok(msg) = WireMessage::from_bytes(&data) {
                                    let response = handle_wire_message(
                                        msg,
                                        remote_addr,
                                        &node_id,
                                        &sk,
                                        &dht,
                                        &connections,
                                        &event_tx,
                                    )
                                    .await;

                                    if let Some(resp) = response {
                                        if let Ok(resp_data) = resp.to_bytes() {
                                            let _ = write_length_prefixed(&mut send, &resp_data).await;
                                        }
                                    }
                                    let _ = send.finish();
                                }
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        tracing::info!("Connection closed by peer: {}", remote_addr);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("Connection error from {}: {}", remote_addr, e);
                        break;
                    }
                }
            }

            // Peer disconnected
            if let Some(nid) = connections.node_id_for_addr(&remote_addr).await {
                connections.set_state(&nid, PeerState::Disconnected).await;
                let _ = event_tx.send(NetworkEvent::PeerDisconnected { node_id: nid });
            }
        });
    }

    /// Send an encrypted message to a peer by address
    pub async fn send_message(
        &self,
        addr: &SocketAddr,
        message_id: String,
        sender_id: String,
        recipient_id: String,
        payload: Vec<u8>,
    ) -> Result<()> {
        let msg = WireMessage::EncryptedMessage {
            message_id,
            sender_id,
            recipient_id,
            payload,
        };
        let data = msg.to_bytes().map_err(Error::Serialization)?;
        self.transport.send_oneshot(addr, &data).await
    }

    /// Store a pre-key bundle in the DHT
    pub async fn broadcast_prekey_bundle(
        &self,
        fingerprint: &str,
        bundle_data: Vec<u8>,
    ) -> Result<()> {
        // Derive a DHT key from the fingerprint
        let key = fingerprint_to_node_id(fingerprint);

        // Store locally
        self.dht
            .write()
            .await
            .store(key, DhtRecord::PreKeyBundle(bundle_data.clone()));

        // Send StoreRecord to closest known nodes
        let closest = self.dht.read().await.find_closest(&key, 3);
        for node in closest {
            let msg = WireMessage::StoreRecord {
                key,
                value: bundle_data.clone(),
                record_type: "prekey_bundle".to_string(),
            };
            if let Ok(data) = msg.to_bytes() {
                let _ = self.transport.send_oneshot(&node.addr, &data).await;
            }
        }

        Ok(())
    }

    /// Discover a peer using iterative Kademlia lookup
    pub async fn discover_peer(&self, target: &NodeId) -> Result<Vec<NodeInfo>> {
        let mut closest = self.dht.read().await.find_closest(target, 3);
        let mut queried = std::collections::HashSet::new();

        // Up to 3 rounds of iterative lookup
        for _round in 0..3 {
            let mut new_nodes = Vec::new();

            for node in &closest {
                if queried.contains(&node.id) {
                    continue;
                }
                queried.insert(node.id);

                let msg = WireMessage::FindNode { target: *target };
                if let Ok(data) = msg.to_bytes() {
                    if let Ok(response_data) = self.transport.send(&node.addr, &data).await {
                        if let Ok(WireMessage::FindNodeResponse { nodes }) =
                            WireMessage::from_bytes(&response_data)
                        {
                            for entry in nodes {
                                let info = NodeInfo {
                                    id: entry.id,
                                    addr: entry.addr,
                                    last_seen: chrono::Utc::now().timestamp(),
                                };
                                self.dht.write().await.add_node(info.clone());
                                new_nodes.push(info);
                            }
                        }
                    }
                }
            }

            if new_nodes.is_empty() {
                break;
            }

            closest = self.dht.read().await.find_closest(target, 3);
        }

        Ok(closest)
    }

    /// Request a pre-key bundle from the network
    pub async fn request_prekey_bundle(&self, fingerprint: &str) -> Result<()> {
        let key = fingerprint_to_node_id(fingerprint);

        // Check local DHT first
        if let Some(records) = self.dht.read().await.get(&key) {
            for record in records {
                if let DhtRecord::PreKeyBundle(data) = record {
                    let _ = self.event_tx.send(NetworkEvent::PreKeyBundleReceived {
                        fingerprint: fingerprint.to_string(),
                        bundle_data: data.clone(),
                    });
                    return Ok(());
                }
            }
        }

        // Query closest nodes
        let closest = self.dht.read().await.find_closest(&key, 3);
        for node in closest {
            let msg = WireMessage::GetRecord { key };
            if let Ok(data) = msg.to_bytes() {
                if let Ok(response_data) = self.transport.send(&node.addr, &data).await {
                    if let Ok(WireMessage::GetRecordResponse { values, .. }) =
                        WireMessage::from_bytes(&response_data)
                    {
                        if let Some(value) = values.into_iter().next() {
                            let _ = self.event_tx.send(NetworkEvent::PreKeyBundleReceived {
                                fingerprint: fingerprint.to_string(),
                                bundle_data: value,
                            });
                            return Ok(());
                        }
                    }
                }
            }
        }

        Err(Error::PeerNotFound(format!(
            "Pre-key bundle not found for {}",
            fingerprint
        )))
    }

    /// Get our node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get the DHT (for direct access)
    pub fn dht(&self) -> &Arc<RwLock<KademliaDht>> {
        &self.dht
    }

    /// Get the connection manager
    pub fn connections(&self) -> &ConnectionManager {
        &self.connections
    }

    /// Get the transport (for direct access)
    pub fn transport(&self) -> &QuicTransport {
        &self.transport
    }
}

/// Handle an incoming wire message and optionally return a response
async fn handle_wire_message(
    msg: WireMessage,
    remote_addr: SocketAddr,
    our_node_id: &NodeId,
    signing_key: &SigningKey,
    dht: &Arc<RwLock<KademliaDht>>,
    connections: &ConnectionManager,
    event_tx: &mpsc::UnboundedSender<NetworkEvent>,
) -> Option<WireMessage> {
    match msg {
        WireMessage::Handshake {
            node_id,
            identity_public_key,
            signature,
            nonce,
            listen_addr: _,
        } => {
            // Verify the peer's handshake signature
            let challenge = build_handshake_challenge(&node_id, &remote_addr, &nonce);
            if let Err(_) = verify_handshake_signature_standalone(&identity_public_key, &signature, &challenge) {
                return Some(WireMessage::Error {
                    code: 401,
                    message: "Handshake signature verification failed".to_string(),
                });
            }

            // Respond with our HandshakeAck
            let mut peer_info = PeerInfo::new(node_id, remote_addr);
            peer_info.identity_public_key = Some(identity_public_key.clone());
            peer_info.state = PeerState::Connected;
            connections.add_peer(peer_info).await;

            dht.write().await.add_node(NodeInfo {
                id: node_id,
                addr: remote_addr,
                last_seen: chrono::Utc::now().timestamp(),
            });

            let _ = event_tx.send(NetworkEvent::PeerConnected {
                node_id,
                addr: remote_addr,
            });

            // Generate our own nonce for the ack
            let ack_nonce: [u8; 32] = rand::random();
            let ack_challenge = build_handshake_challenge(our_node_id, &remote_addr, &ack_nonce);

            Some(WireMessage::HandshakeAck {
                node_id: *our_node_id,
                identity_public_key: signing_key.verifying_key().as_bytes().to_vec(),
                signature: signing_key.sign(&ack_challenge).to_bytes().to_vec(),
                nonce: ack_nonce.to_vec(),
                listen_addr: remote_addr, // we use their addr as we see it
            })
        }

        WireMessage::EncryptedMessage {
            message_id,
            sender_id,
            recipient_id,
            payload,
        } => {
            let _ = event_tx.send(NetworkEvent::MessageReceived {
                sender_id: sender_id.clone(),
                recipient_id: recipient_id.clone(),
                payload,
            });
            Some(WireMessage::MessageAck {
                message_id,
            })
        }

        WireMessage::RequestPreKeyBundle {
            target_fingerprint,
        } => {
            let key = fingerprint_to_node_id(&target_fingerprint);
            if let Some(records) = dht.read().await.get(&key) {
                for record in records {
                    if let DhtRecord::PreKeyBundle(data) = record {
                        return Some(WireMessage::PreKeyBundleResponse {
                            fingerprint: target_fingerprint,
                            bundle_data: data.clone(),
                        });
                    }
                }
            }
            Some(WireMessage::Error {
                code: 404,
                message: "Pre-key bundle not found".to_string(),
            })
        }

        WireMessage::FindNode { target } => {
            let closest = dht.read().await.find_closest(&target, 20);
            let nodes = closest
                .into_iter()
                .map(|n| NodeEntry {
                    id: n.id,
                    addr: n.addr,
                })
                .collect();
            Some(WireMessage::FindNodeResponse { nodes })
        }

        WireMessage::StoreRecord { key, value, record_type } => {
            let record = match record_type.as_str() {
                "prekey_bundle" => DhtRecord::PreKeyBundle(value),
                "offline_message" => DhtRecord::OfflineMessage(value),
                "node_addr" => {
                    // Attempt to deserialize the value as a SocketAddr
                    match bincode::deserialize::<SocketAddr>(&value) {
                        Ok(addr) => DhtRecord::NodeAddr(addr),
                        Err(_) => {
                            return Some(WireMessage::Error {
                                code: 400,
                                message: "Invalid node_addr value".to_string(),
                            });
                        }
                    }
                }
                _ => {
                    return Some(WireMessage::Error {
                        code: 400,
                        message: format!("Unknown record_type: {}", record_type),
                    });
                }
            };
            dht.write().await.store(key, record);
            Some(WireMessage::StoreRecordAck {
                key,
                success: true,
            })
        }

        WireMessage::GetRecord { key } => {
            let values = if let Some(records) = dht.read().await.get(&key) {
                records
                    .iter()
                    .filter_map(|r| match r {
                        DhtRecord::PreKeyBundle(data) => Some(data.clone()),
                        _ => None,
                    })
                    .collect()
            } else {
                vec![]
            };
            Some(WireMessage::GetRecordResponse { key, values })
        }

        WireMessage::Ping { nonce } => Some(WireMessage::Pong { nonce }),

        _ => None,
    }
}

/// Build a handshake challenge by concatenating node_id + peer addr bytes + nonce
fn build_handshake_challenge(node_id: &NodeId, addr: &SocketAddr, nonce: &[u8]) -> Vec<u8> {
    let mut challenge = Vec::new();
    challenge.extend_from_slice(node_id);
    challenge.extend_from_slice(addr.to_string().as_bytes());
    challenge.extend_from_slice(nonce);
    challenge
}

/// Verify a handshake signature (standalone function for use in handle_wire_message)
fn verify_handshake_signature_standalone(public_key_bytes: &[u8], signature_bytes: &[u8], challenge: &[u8]) -> Result<()> {
    if public_key_bytes.len() != 32 {
        return Err(Error::Handshake("Invalid public key length".to_string()));
    }
    if signature_bytes.len() != 64 {
        return Err(Error::Handshake("Invalid signature length".to_string()));
    }

    let key_bytes: [u8; 32] = public_key_bytes.try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Error::Handshake(format!("Invalid public key: {}", e)))?;

    let sig_bytes: [u8; 64] = signature_bytes.try_into().unwrap();
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(challenge, &signature)
        .map_err(|_| Error::Handshake("Invalid handshake signature".to_string()))?;

    Ok(())
}

/// Convert a fingerprint string to a NodeId (BLAKE2s hash)
pub fn fingerprint_to_node_id(fingerprint: &str) -> NodeId {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"VeilComm_FingerprintToNodeId");
    hasher.update(fingerprint.as_bytes());
    let hash = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&hash);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_to_node_id() {
        let id1 = fingerprint_to_node_id("abc123");
        let id2 = fingerprint_to_node_id("abc123");
        let id3 = fingerprint_to_node_id("def456");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }
}
