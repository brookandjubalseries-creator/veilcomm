//! Tor transport implementation
//!
//! Routes connections through a Tor SOCKS5 proxy to reach .onion hidden services.
//! Uses TCP+TLS (rustls) since QUIC (UDP) cannot traverse Tor.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::{PeerAddress, Transport, TransportStream};
use crate::error::{Error, Result};

/// Configuration for the Tor transport
#[derive(Clone, Debug)]
pub struct TorConfig {
    /// SOCKS5 proxy address (default 127.0.0.1:9050)
    pub socks_addr: SocketAddr,
    /// Whether Tor transport is enabled
    pub enabled: bool,
    /// Local TCP port to listen on for incoming Tor connections.
    /// The Tor hidden service (torrc) should map .onion:port -> localhost:this_port
    pub listen_port: u16,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_addr: "127.0.0.1:9050".parse().unwrap(),
            enabled: false,
            listen_port: 9051,
        }
    }
}

/// Tor transport - routes connections via SOCKS5 proxy to .onion addresses
pub struct TorTransport {
    config: TorConfig,
    tls_connector: TlsConnector,
    tls_acceptor: TlsAcceptor,
    /// Local TCP listener for incoming connections (set after start)
    listener_addr: Option<SocketAddr>,
}

/// Custom certificate verifier that accepts any certificate
/// (authentication is at the application layer via Ed25519 signatures)
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

/// Generate a self-signed TLS certificate (same approach as QUIC transport)
fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["veilcomm".to_string()])
        .map_err(|e| Error::Transport(format!("Certificate generation failed: {}", e)))?;

    let cert_der_bytes = cert
        .serialize_der()
        .map_err(|e| Error::Transport(format!("Certificate serialization failed: {}", e)))?;
    let key_der_bytes = cert.serialize_private_key_der();

    let cert_der = CertificateDer::from(cert_der_bytes);
    let key_der = PrivatePkcs8KeyDer::from(key_der_bytes);

    Ok((vec![cert_der], key_der))
}

impl TorTransport {
    /// Create a new Tor transport with the given config
    pub fn new(config: TorConfig) -> Result<Self> {
        let (certs, key) = generate_self_signed_cert()?;

        // Client TLS config (skip server cert verification; we auth at app layer)
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"veilcomm-tor/1".to_vec()];
        let tls_connector = TlsConnector::from(Arc::new(client_crypto));

        // Server TLS config for accepting incoming connections
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key.into())
            .map_err(|e| Error::Transport(format!("TLS server config error: {}", e)))?;
        server_crypto.alpn_protocols = vec![b"veilcomm-tor/1".to_vec()];
        let tls_acceptor = TlsAcceptor::from(Arc::new(server_crypto));

        Ok(Self {
            config,
            tls_connector,
            tls_acceptor,
            listener_addr: None,
        })
    }

    /// Get the TLS acceptor (for the network service to use in the accept loop)
    pub fn tls_acceptor(&self) -> &TlsAcceptor {
        &self.tls_acceptor
    }

    /// Get the config
    pub fn config(&self) -> &TorConfig {
        &self.config
    }

    /// Bind the TCP listener for incoming Tor connections
    pub async fn start_listener(&mut self) -> Result<TcpListener> {
        let bind_addr: SocketAddr = format!("127.0.0.1:{}", self.config.listen_port)
            .parse()
            .map_err(|e| Error::Transport(format!("Invalid listen port: {}", e)))?;
        let listener = TcpListener::bind(bind_addr).await?;
        let actual_addr = listener.local_addr()?;
        self.listener_addr = Some(actual_addr);
        tracing::info!("Tor TCP listener started on {}", actual_addr);
        Ok(listener)
    }

    /// Get the listener address
    pub fn listener_addr(&self) -> Option<SocketAddr> {
        self.listener_addr
    }

    /// Connect to an onion address through the Tor SOCKS5 proxy
    async fn connect_socks5(&self, onion_addr: &str) -> Result<TcpStream> {
        // Parse the onion address into host:port
        let (host, port) = parse_onion_addr(onion_addr)?;

        let stream = tokio_socks::tcp::Socks5Stream::connect(
            self.config.socks_addr,
            (host.as_str(), port),
        )
        .await
        .map_err(|e| Error::Connection(format!("SOCKS5 connect to {} failed: {}", onion_addr, e)))?;

        Ok(stream.into_inner())
    }

    /// Wrap a TCP stream with TLS (client-side)
    async fn wrap_tls_client(&self, stream: TcpStream) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let server_name = rustls::pki_types::ServerName::try_from("veilcomm")
            .map_err(|e| Error::Transport(format!("Invalid server name: {}", e)))?
            .to_owned();

        let tls_stream = self
            .tls_connector
            .connect(server_name, stream)
            .await
            .map_err(|e| Error::Transport(format!("TLS handshake failed: {}", e)))?;

        Ok(tls_stream)
    }

    /// Accept an incoming TCP connection and wrap with TLS
    pub async fn accept_tls(&self, stream: TcpStream) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
        let tls_stream = self
            .tls_acceptor
            .accept(stream)
            .await
            .map_err(|e| Error::Transport(format!("TLS accept failed: {}", e)))?;

        Ok(tls_stream)
    }
}

/// Parse "host.onion:port" into (host, port)
fn parse_onion_addr(addr: &str) -> Result<(String, u16)> {
    if let Some(colon_pos) = addr.rfind(':') {
        let host = addr[..colon_pos].to_string();
        let port: u16 = addr[colon_pos + 1..]
            .parse()
            .map_err(|_| Error::Transport(format!("Invalid port in onion address: {}", addr)))?;
        Ok((host, port))
    } else {
        Err(Error::Transport(format!(
            "Invalid onion address (missing port): {}",
            addr
        )))
    }
}

/// Tor transport stream wrapping a TLS connection over TCP (client side)
pub struct TorClientStream {
    inner: tokio_rustls::client::TlsStream<TcpStream>,
}

/// Tor transport stream wrapping a TLS connection over TCP (server side)
pub struct TorServerStream {
    inner: tokio_rustls::server::TlsStream<TcpStream>,
}

#[async_trait]
impl TransportStream for TorClientStream {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        write_length_prefixed_tcp(&mut self.inner, data).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        read_length_prefixed_tcp(&mut self.inner).await
    }
}

#[async_trait]
impl TransportStream for TorServerStream {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        write_length_prefixed_tcp(&mut self.inner, data).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        read_length_prefixed_tcp(&mut self.inner).await
    }
}

#[async_trait]
impl Transport for TorTransport {
    async fn connect(&self, addr: &PeerAddress) -> Result<Box<dyn TransportStream>> {
        match addr {
            PeerAddress::Onion(onion_addr) => {
                let tcp_stream = self.connect_socks5(onion_addr).await?;
                let tls_stream = self.wrap_tls_client(tcp_stream).await?;
                Ok(Box::new(TorClientStream { inner: tls_stream }))
            }
            PeerAddress::Direct(_) => Err(Error::Transport(
                "TorTransport does not support direct addresses".to_string(),
            )),
        }
    }

    async fn send_and_recv(&self, addr: &PeerAddress, data: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.connect(addr).await?;
        stream.send(data).await?;
        stream.recv().await
    }

    async fn send_oneshot(&self, addr: &PeerAddress, data: &[u8]) -> Result<()> {
        let mut stream = self.connect(addr).await?;
        stream.send(data).await
    }
}

/// Write a length-prefixed message to a TCP/TLS stream
async fn write_length_prefixed_tcp<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    writer
        .write_all(&len)
        .await
        .map_err(|e| Error::Transport(format!("Write length failed: {}", e)))?;
    writer
        .write_all(data)
        .await
        .map_err(|e| Error::Transport(format!("Write data failed: {}", e)))?;
    writer
        .flush()
        .await
        .map_err(|e| Error::Transport(format!("Flush failed: {}", e)))?;
    Ok(())
}

/// Read a length-prefixed message from a TCP/TLS stream
async fn read_length_prefixed_tcp<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Transport(format!("Read length failed: {}", e)))?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(Error::Protocol("Message too large (>16MB)".to_string()));
    }

    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .map_err(|e| Error::Transport(format!("Read data failed: {}", e)))?;

    Ok(data)
}

/// Read a length-prefixed message from a server TLS stream (public for use in service.rs)
pub async fn read_length_prefixed_tls_server(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
) -> Result<Vec<u8>> {
    read_length_prefixed_tcp(stream).await
}

/// Write a length-prefixed message to a server TLS stream (public for use in service.rs)
pub async fn write_length_prefixed_tls_server(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    data: &[u8],
) -> Result<()> {
    write_length_prefixed_tcp(stream, data).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_onion_addr() {
        let (host, port) = parse_onion_addr("abcdef1234567890.onion:9999").unwrap();
        assert_eq!(host, "abcdef1234567890.onion");
        assert_eq!(port, 9999);
    }

    #[test]
    fn test_parse_onion_addr_no_port() {
        assert!(parse_onion_addr("abcdef.onion").is_err());
    }

    #[test]
    fn test_tor_config_default() {
        let config = TorConfig::default();
        assert_eq!(config.socks_addr, "127.0.0.1:9050".parse::<SocketAddr>().unwrap());
        assert!(!config.enabled);
    }

    #[test]
    fn test_peer_address_display() {
        let direct = PeerAddress::Direct("127.0.0.1:8080".parse().unwrap());
        assert_eq!(direct.to_string(), "127.0.0.1:8080");

        let onion = PeerAddress::Onion("abcdef.onion:9999".to_string());
        assert_eq!(onion.to_string(), "abcdef.onion:9999");
    }
}
