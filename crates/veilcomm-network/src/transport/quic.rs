//! QUIC transport implementation
//!
//! Uses quinn for QUIC with rustls for TLS 1.3.
//! TLS certificates are self-signed; authentication is done at the app layer
//! via Ed25519 identity signatures in the handshake.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig, ClientConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::sync::RwLock;

use crate::error::{Error, Result};

/// QUIC transport configuration
pub struct QuicConfig {
    /// Bind address
    pub bind_addr: SocketAddr,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Keep-alive interval in seconds
    pub keep_alive_interval: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            max_connections: 100,
            keep_alive_interval: 15,
        }
    }
}

/// QUIC transport layer
pub struct QuicTransport {
    config: QuicConfig,
    /// The QUIC endpoint
    endpoint: Option<Endpoint>,
    /// Active connections indexed by remote address
    connections: Arc<RwLock<HashMap<SocketAddr, Connection>>>,
}

/// Generate a self-signed TLS certificate for QUIC
fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["veilcomm".to_string()])
        .map_err(|e| Error::Transport(format!("Certificate generation failed: {}", e)))?;

    let cert_der_bytes = cert.serialize_der()
        .map_err(|e| Error::Transport(format!("Certificate serialization failed: {}", e)))?;
    let key_der_bytes = cert.serialize_private_key_der();

    let cert_der = CertificateDer::from(cert_der_bytes);
    let key_der = PrivatePkcs8KeyDer::from(key_der_bytes);

    Ok((vec![cert_der], key_der))
}

/// Custom certificate verifier that accepts any certificate
/// (we authenticate at the application layer via Ed25519 signatures)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

impl QuicTransport {
    /// Create a new QUIC transport
    pub fn new(config: QuicConfig) -> Result<Self> {
        Ok(Self {
            config,
            endpoint: None,
            connections: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Start the transport (bind endpoint)
    pub async fn start(&mut self) -> Result<()> {
        let (certs, key) = generate_self_signed_cert()?;

        // Server config
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.into())
            .map_err(|e| Error::Transport(format!("TLS server config error: {}", e)))?;
        server_crypto.alpn_protocols = vec![b"veilcomm/1".to_vec()];

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| Error::Transport(format!("QUIC server config error: {}", e)))?,
        ));

        let transport = Arc::get_mut(&mut server_config.transport).unwrap();
        transport.keep_alive_interval(Some(Duration::from_secs(self.config.keep_alive_interval)));
        transport.max_concurrent_bidi_streams(self.config.max_connections.into());

        let endpoint = Endpoint::server(server_config, self.config.bind_addr)?;

        tracing::info!("QUIC transport started on {}", endpoint.local_addr()?);

        self.endpoint = Some(endpoint);
        Ok(())
    }

    /// Connect to a remote peer
    pub async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| Error::Transport("Endpoint not started".to_string()))?;

        // Client crypto config
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"veilcomm/1".to_vec()];

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|e| Error::Transport(format!("QUIC client config error: {}", e)))?,
        ));

        let connection = endpoint
            .connect_with(client_config, addr, "veilcomm")
            .map_err(|e| Error::Connection(format!("Connect error: {}", e)))?
            .await
            .map_err(|e| Error::Connection(format!("Connection failed: {}", e)))?;

        tracing::info!("Connected to {}", addr);

        // Store the connection
        self.connections
            .write()
            .await
            .insert(addr, connection.clone());

        Ok(connection)
    }

    /// Send data to a peer over a bidirectional stream
    ///
    /// Messages are length-prefixed: [4-byte big-endian length][payload]
    pub async fn send(&self, addr: &SocketAddr, data: &[u8]) -> Result<Vec<u8>> {
        let connections = self.connections.read().await;
        let conn = connections
            .get(addr)
            .ok_or_else(|| Error::Connection(format!("No connection to {}", addr)))?;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Connection(format!("Failed to open stream: {}", e)))?;

        // Send length-prefixed data
        let len = (data.len() as u32).to_be_bytes();
        send.write_all(&len)
            .await
            .map_err(|e| Error::Transport(format!("Write length failed: {}", e)))?;
        send.write_all(data)
            .await
            .map_err(|e| Error::Transport(format!("Write data failed: {}", e)))?;
        send.finish()
            .map_err(|e| Error::Transport(format!("Finish failed: {}", e)))?;

        // Read response
        let response = read_length_prefixed(&mut recv).await?;
        Ok(response)
    }

    /// Send data without expecting a response (unidirectional pattern on bidi stream)
    pub async fn send_oneshot(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        let connections = self.connections.read().await;
        let conn = connections
            .get(addr)
            .ok_or_else(|| Error::Connection(format!("No connection to {}", addr)))?;

        let (mut send, _recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Connection(format!("Failed to open stream: {}", e)))?;

        let len = (data.len() as u32).to_be_bytes();
        send.write_all(&len)
            .await
            .map_err(|e| Error::Transport(format!("Write length failed: {}", e)))?;
        send.write_all(data)
            .await
            .map_err(|e| Error::Transport(format!("Write data failed: {}", e)))?;
        send.finish()
            .map_err(|e| Error::Transport(format!("Finish failed: {}", e)))?;

        Ok(())
    }

    /// Accept incoming connections in a loop
    ///
    /// For each new connection, calls the handler with (Connection, SocketAddr).
    /// The handler receives a channel sender to forward received messages.
    pub async fn accept_loop<F, Fut>(
        &self,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Connection, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| Error::Transport("Endpoint not started".to_string()))?;

        let connections = self.connections.clone();

        while let Some(incoming) = endpoint.accept().await {
            let remote_addr = incoming.remote_address();
            tracing::info!("Incoming connection from {}", remote_addr);

            match incoming.await {
                Ok(connection) => {
                    connections
                        .write()
                        .await
                        .insert(remote_addr, connection.clone());

                    handler(connection, remote_addr).await;
                }
                Err(e) => {
                    tracing::warn!("Failed to accept connection from {}: {}", remote_addr, e);
                }
            }
        }

        Ok(())
    }

    /// Get the local address of the endpoint
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .as_ref()
            .ok_or_else(|| Error::Transport("Endpoint not started".to_string()))?
            .local_addr()
            .map_err(Error::Io)
    }

    /// Get a connection by address
    pub async fn get_connection(&self, addr: &SocketAddr) -> Option<Connection> {
        self.connections.read().await.get(addr).cloned()
    }

    /// Store a connection
    pub async fn store_connection(&self, addr: SocketAddr, conn: Connection) {
        self.connections.write().await.insert(addr, conn);
    }

    /// Remove a connection
    pub async fn remove_connection(&self, addr: &SocketAddr) {
        self.connections.write().await.remove(addr);
    }

    /// Get the QUIC endpoint (for advanced usage)
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.endpoint.as_ref()
    }
}

/// Read a length-prefixed message from a QUIC recv stream
pub async fn read_length_prefixed(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Transport(format!("Read length failed: {}", e)))?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(Error::Protocol("Message too large (>16MB)".to_string()));
    }

    let mut data = vec![0u8; len];
    recv.read_exact(&mut data)
        .await
        .map_err(|e| Error::Transport(format!("Read data failed: {}", e)))?;

    Ok(data)
}

/// Write a length-prefixed message to a QUIC send stream
pub async fn write_length_prefixed(send: &mut SendStream, data: &[u8]) -> Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    send.write_all(&len)
        .await
        .map_err(|e| Error::Transport(format!("Write length failed: {}", e)))?;
    send.write_all(data)
        .await
        .map_err(|e| Error::Transport(format!("Write data failed: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_creation() {
        let config = QuicConfig::default();
        let transport = QuicTransport::new(config).unwrap();
        assert!(transport.endpoint.is_none());
    }

    #[tokio::test]
    async fn test_transport_start() {
        let config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            max_connections: 10,
            keep_alive_interval: 15,
        };
        let mut transport = QuicTransport::new(config).unwrap();
        transport.start().await.unwrap();
        assert!(transport.endpoint.is_some());
        let addr = transport.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_connect_and_send() {
        // Start a server
        let server_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            max_connections: 10,
            keep_alive_interval: 15,
        };
        let mut server = QuicTransport::new(server_config).unwrap();
        server.start().await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Spawn server accept loop that echoes messages
        let server_connections = server.connections.clone();
        let server_endpoint = server.endpoint.clone().unwrap();
        tokio::spawn(async move {
            if let Some(incoming) = server_endpoint.accept().await {
                if let Ok(conn) = incoming.await {
                    server_connections
                        .write()
                        .await
                        .insert(conn.remote_address(), conn.clone());

                    // Accept a bidi stream and echo
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        if let Ok(data) = read_length_prefixed(&mut recv).await {
                            let _ = write_length_prefixed(&mut send, &data).await;
                            let _ = send.finish();
                        }
                    }
                }
            }
        });

        // Give server time to start accepting
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Start a client
        let client_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            max_connections: 10,
            keep_alive_interval: 15,
        };
        let mut client = QuicTransport::new(client_config).unwrap();
        client.start().await.unwrap();

        // Connect and send
        let _conn = client.connect(server_addr).await.unwrap();
        let response = client.send(&server_addr, b"hello world").await.unwrap();
        assert_eq!(response, b"hello world");
    }
}
