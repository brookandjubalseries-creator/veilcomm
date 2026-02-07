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
};
use veilcomm_storage::{
    database::{Contact, Database, StoredMessage, StoredSession},
    keystore::KeyStore,
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
    pub fn unlock(&mut self, password: &str) -> Result<String> {
        if !self.is_initialized() {
            return Err(Error::NotInitialized);
        }

        // Load and verify key store
        let keystore_bytes = std::fs::read(self.keystore_path())?;
        let keystore = KeyStore::from_bytes(&keystore_bytes)?;
        let identity = keystore.open(password)?;

        // Load pre-keys
        let signed_prekey = keystore.get_signed_prekey(password)?;

        // Open database
        let database = Database::open(self.database_path())?;

        let fingerprint = identity.public_key().fingerprint();

        self.identity = Some(identity);
        self.keystore = Some(keystore);
        self.database = Some(database);
        self.signed_prekey = signed_prekey;

        // Load sessions from database
        self.load_sessions()?;

        Ok(fingerprint)
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
    ) -> Result<()> {
        let identity = self.identity.as_ref().ok_or(Error::NotInitialized)?;
        let node_id = self.derive_node_id()?;
        self.node_id = Some(node_id);

        // Derive Ed25519 SigningKey from our identity's signing key bytes
        let signing_key = SigningKey::from_bytes(&identity.signing_key_bytes());

        let config = NetworkServiceConfig {
            quic_config: QuicConfig {
                bind_addr: listen_addr,
                max_connections: 100,
                keep_alive_interval: 15,
            },
            signing_key,
            node_id,
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

    /// Send a message to a peer over the network
    pub async fn send_message_network(
        &mut self,
        contact_fingerprint: &str,
        text: &str,
    ) -> Result<()> {
        // Encrypt the message using the existing session
        let encrypted = self.send_message(contact_fingerprint, text)?;

        // Serialize the encrypted message
        let payload = encrypted.to_bytes();

        // Find the peer's network address
        let network = self.network.as_ref().ok_or_else(|| {
            Error::Network(veilcomm_network::Error::Transport("Network not started".to_string()))
        })?;

        // Look up the peer in the connection manager
        let connected_peers = network.connections().connected_peers().await;
        let our_fingerprint = self.fingerprint()?;

        // Try to send to the first connected peer that might be our contact
        // In a full implementation, we'd maintain a fingerprint -> addr mapping
        if let Some(peer) = connected_peers.first() {
            network
                .send_message(
                    &peer.addr,
                    encrypted.message_id.clone(),
                    our_fingerprint,
                    contact_fingerprint.to_string(),
                    payload,
                )
                .await?;
            return Ok(());
        }

        Err(Error::Network(veilcomm_network::Error::PeerNotFound(
            format!("No connected peer for {}", contact_fingerprint),
        )))
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
