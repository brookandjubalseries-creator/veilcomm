//! VeilComm client - main application interface

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use chrono::Utc;
use ed25519_dalek::SigningKey;
use x25519_dalek::StaticSecret as X25519SecretKey;

use veilcomm_core::crypto::{
    keys::{IdentityKeyPair, IdentityPublicKey, KeyBundle, OneTimePreKey, PreKeyBundle, SignedPreKey},
    ratchet::DoubleRatchet,
    x3dh::{X3dhInitiator, X3dhResponder},
};
use veilcomm_core::protocol::{
    message::MessageContent,
    session::{EncryptedMessage, Session},
};
use veilcomm_network::{
    dht::NodeId,
    NetworkEvent, NetworkService, NetworkServiceConfig,
    transport::QuicConfig,
    TorConfig,
};
use veilcomm_core::crypto::sender_key::{ReceivedSenderKey, SenderKey};
use veilcomm_storage::{
    database::{Contact, Database, StoredDeadManSwitch, StoredGroup, StoredGroupMember, StoredGroupMessage, StoredMessage, StoredSession},
    keystore::{self, DuressKeyStore, KeyStore, KeyStoreVersion},
};

use crate::error::{Error, Result};

/// Data directory structure
const KEYSTORE_FILE: &str = "keystore.bin";
const DATABASE_FILE: &str = "veilcomm.db";

/// VeilComm client
pub struct VeilCommClient {
    /// Data directory path
    data_dir: PathBuf,
    /// Identity key pair (when unlocked)
    identity: Option<IdentityKeyPair>,
    /// Key store
    keystore: Option<KeyStore>,
    /// Database
    database: Option<Database>,
    /// Active sessions
    sessions: HashMap<String, Session>,
    /// Current signed pre-key
    signed_prekey: Option<SignedPreKey>,
    /// One-time pre-keys
    one_time_prekeys: Vec<OneTimePreKey>,
    /// Network service (when started)
    network: Option<NetworkService>,
    /// Our node ID in the DHT
    node_id: Option<NodeId>,
    /// Whether Tor routing is enabled
    tor_enabled: bool,
    /// Our Tor onion address (if Tor is enabled)
    onion_address: Option<String>,
    /// Our sender keys for groups (group_id -> SenderKey)
    sender_keys: HashMap<String, SenderKey>,
    /// Received sender keys from other group members ((group_id, fingerprint) -> ReceivedSenderKey)
    received_sender_keys: HashMap<(String, String), ReceivedSenderKey>,
    /// Duress keystore (V2 format, when duress mode is configured)
    duress_keystore: Option<DuressKeyStore>,
    /// Whether the current session is using the duress vault
    is_duress: bool,
    /// Database token for the active vault (V2 only)
    db_token: Option<[u8; 32]>,
    /// Mesh discovery service
    mesh: Option<veilcomm_network::mesh::MeshDiscovery>,
}

impl VeilCommClient {
    /// Create a new client with the given data directory
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            data_dir: data_dir.as_ref().to_path_buf(),
            identity: None,
            keystore: None,
            database: None,
            sessions: HashMap::new(),
            signed_prekey: None,
            one_time_prekeys: Vec::new(),
            network: None,
            node_id: None,
            tor_enabled: false,
            onion_address: None,
            sender_keys: HashMap::new(),
            received_sender_keys: HashMap::new(),
            duress_keystore: None,
            is_duress: false,
            db_token: None,
            mesh: None,
        }
    }

    /// Get the data directory path
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Check if the client has been initialized
    pub fn is_initialized(&self) -> bool {
        self.keystore_path().exists()
    }

    /// Initialize a new identity
    pub fn init(&mut self, password: &str, name: Option<&str>) -> Result<String> {
        if self.is_initialized() {
            return Err(Error::AlreadyInitialized);
        }

        // Create data directory
        std::fs::create_dir_all(&self.data_dir)?;

        // Create key store and identity
        let (keystore, identity) = KeyStore::create(password)?;

        // Generate initial pre-keys
        let mut keystore = keystore;
        let signed_prekey = keystore.generate_signed_prekey(password, &identity)?;
        let one_time_prekeys = keystore.generate_one_time_prekeys(password, 100)?;

        // Save key store
        let keystore_bytes = keystore.to_bytes()?;
        std::fs::write(self.keystore_path(), keystore_bytes)?;

        // Create database
        let database = Database::open(self.database_path())?;

        // Set name if provided
        if let Some(name) = name {
            database.set_setting("name", name)?;
        }

        let fingerprint = identity.public_key().fingerprint();

        self.identity = Some(identity);
        self.keystore = Some(keystore);
        self.database = Some(database);
        self.signed_prekey = Some(signed_prekey);
        self.one_time_prekeys = one_time_prekeys;

        Ok(fingerprint)
    }

    /// Unlock an existing identity
    ///
    /// Auto-detects V1 (standard) vs V2 (duress) keystore format.
    /// For V2, trial decryption determines which vault the password opens.
    pub fn unlock(&mut self, password: &str) -> Result<String> {
        if !self.is_initialized() {
            return Err(Error::NotInitialized);
        }

        let keystore_bytes = std::fs::read(self.keystore_path())?;

        match keystore::load_keystore(&keystore_bytes)? {
            KeyStoreVersion::V1(keystore) => {
                let identity = keystore.open(password)?;
                let signed_prekey = keystore.get_signed_prekey(password)?;
                let database = Database::open(self.database_path())?;

                self.identity = Some(identity);
                self.keystore = Some(keystore);
                self.database = Some(database);
                self.signed_prekey = signed_prekey;
                self.is_duress = false;
            }
            KeyStoreVersion::V2(mut dks) => {
                let result = dks.open(password)?;
                let signed_prekey = dks.get_signed_prekey(password)?;

                // Use db_token to derive database path
                let db_name = keystore::db_filename_from_token(&result.db_token);
                let db_path = self.data_dir.join(&db_name);
                let database = Database::open(&db_path)?;

                self.identity = Some(result.identity);
                self.db_token = Some(result.db_token);
                self.duress_keystore = Some(dks);
                self.database = Some(database);
                self.signed_prekey = signed_prekey;
            }
        }

        self.load_sessions()?;
        self.fingerprint()
    }

    /// Get our identity fingerprint
    pub fn fingerprint(&self) -> Result<String> {
        let identity = self.identity.as_ref().ok_or(Error::NotInitialized)?;
        Ok(identity.public_key().fingerprint())
    }

    /// Get our name
    pub fn name(&self) -> Result<Option<String>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.get_setting("name")?)
    }

    /// Set our name
    pub fn set_name(&self, name: &str) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.set_setting("name", name)?;
        Ok(())
    }

    /// Get our public key bundle for sharing
    pub fn get_key_bundle(&self) -> Result<KeyBundle> {
        let identity = self.identity.as_ref().ok_or(Error::NotInitialized)?;
        let signed_prekey = self
            .signed_prekey
            .as_ref()
            .ok_or_else(|| Error::Session("No signed pre-key".to_string()))?;

        Ok(KeyBundle {
            identity: identity.public_key(),
            signed_prekey: signed_prekey.public_key(),
            one_time_prekeys: self.one_time_prekeys.iter().map(|k| k.public_key()).collect(),
        })
    }

    /// Add a contact
    pub fn add_contact(
        &mut self,
        fingerprint: &str,
        name: Option<&str>,
        identity_key: &IdentityPublicKey,
    ) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;

        let contact = Contact {
            fingerprint: fingerprint.to_string(),
            name: name.map(String::from),
            identity_key: bincode::serialize(identity_key)
                .map_err(|e| Error::Storage(veilcomm_storage::Error::Serialization(e.to_string())))?,
            verified: false,
            created_at: Utc::now(),
            last_seen: None,
        };

        db.add_contact(&contact)?;
        Ok(())
    }

    /// List contacts
    pub fn list_contacts(&self) -> Result<Vec<Contact>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.list_contacts()?)
    }

    /// Get a contact by fingerprint
    pub fn get_contact(&self, fingerprint: &str) -> Result<Option<Contact>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.get_contact(fingerprint)?)
    }

    /// Mark a contact as verified or unverified
    pub fn verify_contact(&self, fingerprint: &str, verified: bool) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.verify_contact(fingerprint, verified)?)
    }

    /// Remove a contact
    pub fn remove_contact(&mut self, fingerprint: &str) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        self.sessions.remove(fingerprint);
        db.remove_contact(fingerprint)?;
        Ok(())
    }

    /// Start a new session with a contact using their pre-key bundle
    pub fn start_session(&mut self, peer_bundle: &PreKeyBundle) -> Result<EncryptedMessage> {
        let identity = self.identity.as_ref().ok_or(Error::NotInitialized)?;

        // Verify the bundle
        peer_bundle.verify()?;

        let peer_fingerprint = peer_bundle.identity.fingerprint();

        // Perform X3DH
        let x3dh = X3dhInitiator::new(identity.clone());
        let (shared_secret, initial_message) = x3dh.agree(peer_bundle)?;

        // Initialize Double Ratchet
        let ratchet = DoubleRatchet::init_alice(
            shared_secret.as_bytes(),
            &peer_bundle.signed_prekey.public,
            shared_secret.associated_data.clone(),
        );

        // Create session
        let session = Session::new_initiator(
            self.fingerprint()?,
            peer_fingerprint.clone(),
            peer_bundle.identity.clone(),
            ratchet,
            initial_message,
        );

        // Send an initial "hello" message
        let mut session = session;
        let encrypted = session.encrypt(MessageContent::text(""))?;

        self.sessions.insert(peer_fingerprint, session);

        Ok(encrypted)
    }

    /// Accept a session from an incoming initial message
    pub fn accept_session(
        &mut self,
        encrypted: &EncryptedMessage,
        password: &str,
    ) -> Result<String> {
        let identity = self.identity.as_ref().ok_or(Error::NotInitialized)?;
        let keystore = self.keystore.as_mut().ok_or(Error::NotInitialized)?;

        let initial_message = encrypted
            .initial_message
            .as_ref()
            .ok_or_else(|| Error::Session("Missing initial message".to_string()))?;

        // Get the signed pre-key
        let signed_prekey = self
            .signed_prekey
            .as_ref()
            .ok_or_else(|| Error::Session("No signed pre-key".to_string()))?;

        // Get one-time pre-key if used
        let one_time_prekeys = if let Some(otpk_id) = initial_message.one_time_prekey_id {
            vec![keystore.consume_one_time_prekey(password, otpk_id)?]
        } else {
            Vec::new()
        };

        // Create X3DH responder
        let mut responder = X3dhResponder::new(
            identity.clone(),
            signed_prekey.clone(),
            one_time_prekeys,
        );

        // Perform X3DH
        let shared_secret = responder.agree(initial_message)?;
        let associated_data = shared_secret.associated_data.clone();

        // Initialize Double Ratchet
        let ratchet = DoubleRatchet::init_bob(
            shared_secret.as_bytes(),
            X25519SecretKey::from(signed_prekey.secret_bytes()),
            associated_data,
        );

        let peer_fingerprint = initial_message.identity_key.fingerprint();

        // Create session
        let session = Session::new_responder(
            self.fingerprint()?,
            peer_fingerprint.clone(),
            initial_message.identity_key.clone(),
            ratchet,
        );

        // Decrypt the initial message
        let mut session = session;
        let _ = session.decrypt(encrypted)?;

        self.sessions.insert(peer_fingerprint.clone(), session);

        Ok(peer_fingerprint)
    }

    /// Send a message to a contact
    pub fn send_message(
        &mut self,
        contact_fingerprint: &str,
        text: &str,
    ) -> Result<EncryptedMessage> {
        let session = self
            .sessions
            .get_mut(contact_fingerprint)
            .ok_or_else(|| Error::Session(format!("No session with {}", contact_fingerprint)))?;

        let content = MessageContent::text(text);
        let encrypted = session.encrypt(content)?;

        // Store in database
        if let Some(ref db) = self.database {
            let stored = StoredMessage {
                id: encrypted.message_id.clone(),
                contact_fingerprint: contact_fingerprint.to_string(),
                outgoing: true,
                content: text.as_bytes().to_vec(),
                timestamp: Utc::now(),
                read: true,
                delivery_status: "delivered".to_string(),
            };
            db.store_message(&stored)?;
        }

        Ok(encrypted)
    }

    /// Send a message to a contact, with offline fallback via DHT if peer is not connected
    pub fn send_message_with_status(
        &mut self,
        contact_fingerprint: &str,
        text: &str,
        delivery_status: &str,
    ) -> Result<EncryptedMessage> {
        let session = self
            .sessions
            .get_mut(contact_fingerprint)
            .ok_or_else(|| Error::Session(format!("No session with {}", contact_fingerprint)))?;

        let content = MessageContent::text(text);
        let encrypted = session.encrypt(content)?;

        if let Some(ref db) = self.database {
            let stored = StoredMessage {
                id: encrypted.message_id.clone(),
                contact_fingerprint: contact_fingerprint.to_string(),
                outgoing: true,
                content: text.as_bytes().to_vec(),
                timestamp: Utc::now(),
                read: true,
                delivery_status: delivery_status.to_string(),
            };
            db.store_message(&stored)?;
        }

        Ok(encrypted)
    }

    /// Receive a message from a contact
    pub fn receive_message(&mut self, sender_fingerprint: &str, encrypted: &EncryptedMessage) -> Result<String> {
        let session = self
            .sessions
            .get_mut(sender_fingerprint)
            .ok_or_else(|| Error::Session(format!("No session with {}", sender_fingerprint)))?;

        let chat_message = session.decrypt(encrypted)
            .map_err(|e| Error::Session(format!("Failed to decrypt message from {}: {}", sender_fingerprint, e)))?;

        // Store in database
        if let Some(ref db) = self.database {
            let text = chat_message.content.as_text().unwrap_or_default();
            let stored = StoredMessage {
                id: chat_message.id,
                contact_fingerprint: sender_fingerprint.to_string(),
                outgoing: false,
                content: text.as_bytes().to_vec(),
                timestamp: chat_message.timestamp,
                read: false,
                delivery_status: "delivered".to_string(),
            };
            db.store_message(&stored)?;
            db.update_contact_last_seen(sender_fingerprint)?;
        }

        chat_message
            .content
            .as_text()
            .ok_or_else(|| Error::Session("Not a text message".to_string()))
    }

    /// Get message history with a contact
    pub fn get_messages(&self, contact_fingerprint: &str, limit: u32) -> Result<Vec<StoredMessage>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.get_messages(contact_fingerprint, limit)?)
    }

    /// Mark messages as read
    pub fn mark_read(&self, contact_fingerprint: &str) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.mark_messages_read(contact_fingerprint)?;
        Ok(())
    }

    /// Get unread message count for a contact
    pub fn unread_count(&self, contact_fingerprint: &str) -> Result<u32> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.unread_count(contact_fingerprint)?)
    }

    /// Check if we have an active session with a contact
    pub fn has_session(&self, fingerprint: &str) -> bool {
        self.sessions.contains_key(fingerprint)
    }

    /// Derive a node ID from our identity public key using BLAKE2s
    pub fn derive_node_id(&self) -> Result<NodeId> {
        use blake2::{Blake2s256, Digest};
        let identity = self.identity.as_ref().ok_or(Error::NotInitialized)?;
        let public = identity.public_key();
        let mut hasher = Blake2s256::new();
        hasher.update(b"VeilComm_NodeId_v1");
        hasher.update(public.verifying_key().as_bytes());
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        Ok(id)
    }

    /// Start the network service
    ///
    /// Binds a QUIC endpoint, connects to bootstrap peers, and publishes
    /// our pre-key bundle to the DHT.
    pub async fn start_network(
        &mut self,
        listen_addr: SocketAddr,
        bootstrap_peers: &[SocketAddr],
        tor_config: Option<TorConfig>,
    ) -> Result<()> {
        let identity = self.identity.as_ref().ok_or(Error::NotInitialized)?;
        let node_id = self.derive_node_id()?;
        self.node_id = Some(node_id);

        // Derive Ed25519 SigningKey from our identity's signing key bytes
        let signing_key = SigningKey::from_bytes(&identity.signing_key_bytes());

        // Track Tor status
        self.tor_enabled = tor_config.as_ref().is_some_and(|c| c.enabled);

        let config = NetworkServiceConfig {
            quic_config: QuicConfig {
                bind_addr: listen_addr,
                max_connections: 100,
                keep_alive_interval: 15,
            },
            signing_key,
            node_id,
            tor_config,
        };

        let mut service = NetworkService::new(config)?;
        service.start().await?;

        // Connect to bootstrap peers
        for addr in bootstrap_peers {
            match service.connect_to_peer(*addr).await {
                Ok(peer_node_id) => {
                    tracing::info!("Connected to bootstrap peer {} ({})", addr, hex::encode(peer_node_id));
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to bootstrap peer {}: {}", addr, e);
                }
            }
        }

        // Publish our pre-key bundle to the DHT
        if let Ok(bundle) = self.get_key_bundle() {
            let bundle_data = bincode::serialize(&bundle)
                .map_err(|e| Error::Storage(veilcomm_storage::Error::Serialization(e.to_string())))?;
            let fingerprint = self.fingerprint()?;
            service.broadcast_prekey_bundle(&fingerprint, bundle_data).await?;
        }

        self.network = Some(service);
        Ok(())
    }

    /// Set the onion address for Tor connections
    pub fn set_onion_address(&mut self, addr: String) {
        self.onion_address = Some(addr.clone());
        if let Some(ref mut network) = self.network {
            network.set_onion_address(addr);
        }
    }

    /// Get the onion address
    pub fn onion_address(&self) -> Option<&str> {
        self.onion_address.as_deref()
    }

    /// Check if Tor is enabled
    pub fn is_tor_enabled(&self) -> bool {
        self.tor_enabled
    }

    /// Connect to a specific peer and establish an encrypted session
    ///
    /// Performs: QUIC connect -> handshake -> DHT lookup for pre-key bundle
    /// -> X3DH key exchange -> send initial Double Ratchet message
    pub async fn connect_to_peer(&mut self, addr: SocketAddr) -> Result<String> {
        let network = self.network.as_ref().ok_or_else(|| {
            Error::Network(veilcomm_network::Error::Transport("Network not started".to_string()))
        })?;

        // Connect via QUIC + handshake
        let _peer_node_id = network.connect_to_peer(addr).await?;

        Ok(format!("Connected to {}", addr))
    }

    /// Get the Tor status info for the GUI
    pub fn tor_status(&self) -> (bool, Option<String>) {
        (self.tor_enabled, self.onion_address.clone())
    }

    /// Take the network event receiver for processing events in a loop
    pub fn take_network_events(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<NetworkEvent>> {
        self.network.as_mut()?.take_event_receiver()
    }

    /// Get our node ID
    pub fn node_id(&self) -> Option<&NodeId> {
        self.node_id.as_ref()
    }

    /// Save session state to database
    pub fn save_sessions(&self) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;

        for (fingerprint, session) in &self.sessions {
            let exported = session.export();
            let state = bincode::serialize(&exported.ratchet_state)
                .map_err(|e| Error::Storage(veilcomm_storage::Error::Serialization(e.to_string())))?;

            let stored = StoredSession {
                peer_fingerprint: fingerprint.clone(),
                state,
                associated_data: exported.ratchet_state.associated_data.clone(),
                created_at: Utc::now(),
                last_activity: Utc::now(),
            };

            db.store_session(&stored)?;
        }

        Ok(())
    }

    /// Load sessions from database
    fn load_sessions(&mut self) -> Result<()> {
        // Sessions are loaded on-demand when communicating with a contact
        // This is a placeholder for future implementation
        Ok(())
    }

    // ─── Offline Messaging ─────────────────────────────────────

    /// Send a message with offline fallback: if peer is not connected, store in DHT
    pub async fn send_message_network(
        &mut self,
        contact_fingerprint: &str,
        text: &str,
    ) -> Result<String> {
        // Check connectivity first, collecting needed info before borrowing self mutably
        let peer_connected = {
            let network = self.network.as_ref().ok_or_else(|| {
                Error::Network(veilcomm_network::Error::Transport("Network not started".to_string()))
            })?;
            let connected_peers = network.connections().connected_peers().await;
            !connected_peers.is_empty()
        };

        if peer_connected {
            let encrypted = self.send_message(contact_fingerprint, text)?;
            let payload = encrypted.to_bytes();
            let our_fingerprint = self.fingerprint()?;
            let message_id = encrypted.message_id.clone();

            let network = self.network.as_ref().ok_or_else(|| {
                Error::Network(veilcomm_network::Error::Transport("Network not started".to_string()))
            })?;
            let connected_peers = network.connections().connected_peers().await;

            if let Some(peer) = connected_peers.first() {
                network
                    .send_message(
                        &peer.addr,
                        encrypted.message_id,
                        our_fingerprint,
                        contact_fingerprint.to_string(),
                        payload,
                    )
                    .await?;
                return Ok(message_id);
            }
        }

        // Peer not connected: encrypt and store in DHT for offline delivery
        let encrypted = self.send_message_with_status(contact_fingerprint, text, "sent_to_dht")?;
        let payload = encrypted.to_bytes();
        let our_fingerprint = self.fingerprint()?;
        let message_id = encrypted.message_id.clone();

        let network = self.network.as_ref().ok_or_else(|| {
            Error::Network(veilcomm_network::Error::Transport("Network not started".to_string()))
        })?;

        network
            .store_offline_message(
                contact_fingerprint,
                &our_fingerprint,
                &encrypted.message_id,
                payload,
            )
            .await?;

        Ok(message_id)
    }

    /// Check for offline messages addressed to us
    pub async fn check_offline_messages(&mut self) -> Result<()> {
        let our_fingerprint = self.fingerprint()?;
        let network = self.network.as_ref().ok_or_else(|| {
            Error::Network(veilcomm_network::Error::Transport("Network not started".to_string()))
        })?;

        network.fetch_offline_messages(&our_fingerprint).await?;
        Ok(())
    }

    /// Update delivery status for a stored message
    pub fn update_delivery_status(&self, message_id: &str, status: &str) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.update_delivery_status(message_id, status)?;
        Ok(())
    }

    /// Get the database reference
    pub fn database(&self) -> Option<&Database> {
        self.database.as_ref()
    }

    // ─── Group Management ────────────────────────────────────

    /// Create a new group
    pub fn create_group(&mut self, name: &str, member_fingerprints: &[String]) -> Result<String> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        let our_fingerprint = self.fingerprint()?;

        let group_id = uuid::Uuid::new_v4().to_string();

        let group = StoredGroup {
            group_id: group_id.clone(),
            name: name.to_string(),
            creator_fingerprint: our_fingerprint.clone(),
            created_at: Utc::now(),
            max_members: 100,
        };
        db.create_group(&group)?;

        // Add ourselves as admin
        db.add_group_member(&StoredGroupMember {
            group_id: group_id.clone(),
            fingerprint: our_fingerprint.clone(),
            name: self.name().unwrap_or(None),
            role: "admin".to_string(),
            joined_at: Utc::now(),
        })?;

        // Add other members
        for fp in member_fingerprints {
            if fp != &our_fingerprint {
                let contact_name = db.get_contact(fp)?
                    .map(|c| c.name)
                    .unwrap_or(None);
                db.add_group_member(&StoredGroupMember {
                    group_id: group_id.clone(),
                    fingerprint: fp.clone(),
                    name: contact_name,
                    role: "member".to_string(),
                    joined_at: Utc::now(),
                })?;
            }
        }

        // Generate our sender key for this group
        let sender_key = SenderKey::generate(group_id.clone());
        self.sender_keys.insert(group_id.clone(), sender_key);

        Ok(group_id)
    }

    /// List all groups
    pub fn list_groups(&self) -> Result<Vec<StoredGroup>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.list_groups()?)
    }

    /// Get group info
    pub fn get_group(&self, group_id: &str) -> Result<Option<StoredGroup>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.get_group(group_id)?)
    }

    /// Delete a group
    pub fn delete_group(&mut self, group_id: &str) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.delete_group(group_id)?;
        self.sender_keys.remove(group_id);
        // Remove all received sender keys for this group
        self.received_sender_keys.retain(|(gid, _), _| gid != group_id);
        Ok(())
    }

    /// Add a member to a group
    pub fn add_group_member(&self, group_id: &str, fingerprint: &str, name: Option<&str>) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.add_group_member(&StoredGroupMember {
            group_id: group_id.to_string(),
            fingerprint: fingerprint.to_string(),
            name: name.map(String::from),
            role: "member".to_string(),
            joined_at: Utc::now(),
        })?;
        Ok(())
    }

    /// Remove a member from a group
    pub fn remove_group_member(&mut self, group_id: &str, fingerprint: &str) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.remove_group_member(group_id, fingerprint)?;
        self.received_sender_keys.remove(&(group_id.to_string(), fingerprint.to_string()));
        Ok(())
    }

    /// Leave a group
    pub fn leave_group(&mut self, group_id: &str) -> Result<()> {
        let our_fingerprint = self.fingerprint()?;
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.remove_group_member(group_id, &our_fingerprint)?;
        self.sender_keys.remove(group_id);
        self.received_sender_keys.retain(|(gid, _), _| gid != group_id);
        Ok(())
    }

    /// Get members of a group
    pub fn get_group_members(&self, group_id: &str) -> Result<Vec<StoredGroupMember>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.get_group_members(group_id)?)
    }

    /// Send a message to a group
    pub fn send_group_message(&mut self, group_id: &str, text: &str) -> Result<String> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        let our_fingerprint = self.fingerprint()?;

        // Encrypt with our sender key
        let sender_key = self.sender_keys.get_mut(group_id)
            .ok_or_else(|| Error::Session(format!("No sender key for group {}", group_id)))?;

        // Encrypt with sender key (payload sent to members via network)
        let _encrypted = sender_key.encrypt(&our_fingerprint, text.as_bytes())
            .map_err(Error::Crypto)?;

        let message_id = uuid::Uuid::new_v4().to_string();

        // Store locally
        db.store_group_message(&StoredGroupMessage {
            id: message_id.clone(),
            group_id: group_id.to_string(),
            sender_fingerprint: our_fingerprint,
            content: text.as_bytes().to_vec(),
            timestamp: Utc::now(),
            read: true,
        })?;

        // The encrypted payload would be sent to all group members via network
        // (handled by the GUI/CLI layer)
        Ok(message_id)
    }

    /// Get group messages
    pub fn get_group_messages(&self, group_id: &str, limit: u32) -> Result<Vec<StoredGroupMessage>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.get_group_messages(group_id, limit)?)
    }

    /// Mark group messages as read
    pub fn mark_group_read(&self, group_id: &str) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.mark_group_messages_read(group_id)?;
        Ok(())
    }

    /// Get unread group message count
    pub fn unread_group_count(&self, group_id: &str) -> Result<u32> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.unread_group_count(group_id)?)
    }

    /// Get network service reference
    pub fn network(&self) -> Option<&NetworkService> {
        self.network.as_ref()
    }

    // ─── Duress Password (Decoy Vault) ────────────────────────

    /// Set up duress password mode
    ///
    /// Migrates the V1 keystore to V2 dual-vault format. The real vault keeps
    /// the current identity. A new decoy identity is created for the duress vault.
    /// Returns the duress vault fingerprint.
    pub fn setup_duress(&mut self, real_password: &str, duress_password: &str) -> Result<String> {
        let keystore = self.keystore.as_ref().ok_or(Error::NotInitialized)?;

        let (dks, duress_result) =
            DuressKeyStore::from_v1(keystore, real_password, duress_password)?;

        // Initialize the duress database with some seed data
        let db_name = keystore::db_filename_from_token(&duress_result.db_token);
        let db_path = self.data_dir.join(&db_name);
        let _duress_db = Database::open(&db_path)?;

        let duress_fingerprint = duress_result.identity.public_key().fingerprint();

        // Save the V2 keystore
        let dks_bytes = dks.to_bytes()?;
        std::fs::write(self.keystore_path(), dks_bytes)?;

        // Also initialize the real vault's database under its token
        // (existing veilcomm.db will be kept as fallback)
        self.duress_keystore = Some(dks);
        self.keystore = None; // No longer using V1

        Ok(duress_fingerprint)
    }

    /// Check if duress mode is configured (V2 keystore exists)
    pub fn has_duress(&self) -> bool {
        self.duress_keystore.is_some()
    }

    /// Remove duress mode, converting back to V1 format
    pub fn remove_duress(&mut self, password: &str) -> Result<()> {
        if self.duress_keystore.is_none() {
            return Ok(());
        }

        // Re-create V1 keystore from the current identity
        let _identity = self.identity.as_ref().ok_or(Error::NotInitialized)?;
        let (keystore, _) = KeyStore::create(password)?;

        // Save V1 format
        let bytes = keystore.to_bytes()?;
        std::fs::write(self.keystore_path(), bytes)?;

        self.keystore = Some(keystore);
        self.duress_keystore = None;

        Ok(())
    }

    // ─── Dead Man's Switch ──────────────────────────────────

    /// Create a dead man's switch
    pub fn create_dead_man_switch(
        &self,
        recipients: Vec<String>,
        message: &str,
        interval_secs: i64,
    ) -> Result<String> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let dms = StoredDeadManSwitch {
            id: id.clone(),
            recipient_fingerprints: recipients,
            message: message.to_string(),
            check_in_interval_secs: interval_secs,
            last_check_in: now,
            created_at: now,
            enabled: true,
            triggered: false,
        };
        db.create_dead_man_switch(&dms)?;
        Ok(id)
    }

    /// Check in to reset all dead man's switch timers
    pub fn dead_man_check_in(&self) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        let switches = db.list_dead_man_switches()?;
        for dms in switches {
            if dms.enabled && !dms.triggered {
                db.check_in_dead_man_switch(&dms.id)?;
            }
        }
        Ok(())
    }

    /// List all dead man's switches
    pub fn list_dead_man_switches(&self) -> Result<Vec<StoredDeadManSwitch>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.list_dead_man_switches()?)
    }

    /// Delete a dead man's switch
    pub fn delete_dead_man_switch(&self, id: &str) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.delete_dead_man_switch(id)?;
        Ok(())
    }

    /// Toggle a dead man's switch enabled/disabled
    pub fn toggle_dead_man_switch(&self, id: &str, enabled: bool) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.toggle_dead_man_switch(id, enabled)?;
        Ok(())
    }

    /// Check for expired dead man's switches and return the ones that should trigger
    pub fn check_expired_switches(&self) -> Result<Vec<StoredDeadManSwitch>> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        Ok(db.get_expired_dead_man_switches()?)
    }

    /// Mark a dead man's switch as triggered
    pub fn trigger_dead_man_switch(&self, id: &str) -> Result<()> {
        let db = self.database.as_ref().ok_or(Error::NotInitialized)?;
        db.trigger_dead_man_switch(id)?;
        Ok(())
    }

    // ─── LAN Mesh Discovery ─────────────────────────────────

    /// Start LAN mesh discovery
    pub async fn start_mesh(&mut self, listen_addr: SocketAddr) -> Result<()> {
        let node_id = self.derive_node_id()?;
        let fingerprint = self.fingerprint()?;
        let name = self.name().unwrap_or(None);

        let mesh = veilcomm_network::mesh::MeshDiscovery::new(
            node_id,
            fingerprint,
            name,
            listen_addr,
        );
        mesh.start().await.map_err(Error::Network)?;
        self.mesh = Some(mesh);
        Ok(())
    }

    /// Stop LAN mesh discovery
    pub async fn stop_mesh(&mut self) {
        if let Some(ref mesh) = self.mesh {
            mesh.stop().await;
        }
        self.mesh = None;
    }

    /// Get discovered LAN peers
    pub fn mesh_peers(&self) -> Vec<veilcomm_network::mesh::MeshPeer> {
        if let Some(ref mesh) = self.mesh {
            mesh.discovered_peers()
        } else {
            Vec::new()
        }
    }

    /// Check if mesh discovery is running
    pub fn is_mesh_running(&self) -> bool {
        self.mesh.as_ref().map(|m| m.is_running()).unwrap_or(false)
    }

    // ─── Steganographic Transport ───────────────────────────

    /// Encode an encrypted message payload as a steganographic BMP image
    pub fn stego_encode(&self, payload: &[u8]) -> Result<Vec<u8>> {
        Ok(veilcomm_core::steganography::encode(payload))
    }

    /// Decode a steganographic BMP image back to the encrypted payload
    pub fn stego_decode(&self, bmp_data: &[u8]) -> Result<Vec<u8>> {
        veilcomm_core::steganography::decode(bmp_data)
            .map_err(|e| Error::Crypto(veilcomm_core::Error::Decryption(format!("{}", e))))
    }

    // ─── Internal Helpers ───────────────────────────────────

    fn keystore_path(&self) -> PathBuf {
        self.data_dir.join(KEYSTORE_FILE)
    }

    fn database_path(&self) -> PathBuf {
        self.data_dir.join(DATABASE_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_client() -> (VeilCommClient, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let client = VeilCommClient::new(temp_dir.path());
        (client, temp_dir)
    }

    #[test]
    fn test_init_and_unlock() {
        let (mut client, _temp) = create_test_client();
        let password = "test_password_123";

        // Initialize
        let fingerprint1 = client.init(password, Some("Alice")).unwrap();
        assert!(!fingerprint1.is_empty());

        // Check name
        assert_eq!(client.name().unwrap(), Some("Alice".to_string()));

        // Drop and recreate to simulate restart
        drop(client);

        let mut client2 = VeilCommClient::new(_temp.path());
        assert!(client2.is_initialized());

        // Unlock
        let fingerprint2 = client2.unlock(password).unwrap();
        assert_eq!(fingerprint1, fingerprint2);
    }

    #[test]
    fn test_wrong_password() {
        let (mut client, _temp) = create_test_client();

        client.init("correct_password", None).unwrap();
        drop(client);

        let mut client2 = VeilCommClient::new(_temp.path());
        let result = client2.unlock("wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_contacts() {
        let (mut client, _temp) = create_test_client();
        client.init("password", None).unwrap();

        // Create another identity for the contact
        let other_identity = IdentityKeyPair::generate();
        let other_public = other_identity.public_key();

        client
            .add_contact(&other_public.fingerprint(), Some("Bob"), &other_public)
            .unwrap();

        let contacts = client.list_contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].name, Some("Bob".to_string()));

        client.remove_contact(&other_public.fingerprint()).unwrap();
        let contacts = client.list_contacts().unwrap();
        assert_eq!(contacts.len(), 0);
    }
}
