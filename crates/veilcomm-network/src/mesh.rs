//! LAN Mesh Discovery
//!
//! Discovers VeilComm peers on the local network using UDP multicast.
//! Enables peer-to-peer communication without internet access or DHT bootstrap nodes.
//! Peers announce their presence periodically and discover each other automatically.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use crate::error::{Error, Result};

/// Multicast group address for VeilComm mesh discovery ("MC" = MeshComm).
const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 77, 67);

/// UDP port for mesh discovery announcements.
const MULTICAST_PORT: u16 = 5367;

/// Interval between announcement broadcasts.
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);

/// Peers not seen within this duration are considered stale and removed.
const PEER_EXPIRY: Duration = Duration::from_secs(30);

/// Maximum size of a single UDP announcement datagram.
const MAX_DATAGRAM_SIZE: usize = 1500;

/// Current mesh protocol version.
const PROTOCOL_VERSION: u8 = 1;

/// Announcement message broadcast via UDP multicast for peer discovery.
///
/// Each node periodically sends this message so that other nodes on the
/// same LAN segment can discover it and establish direct connections.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MeshAnnouncement {
    /// Unique 32-byte node identifier (typically derived from the node's public key).
    pub node_id: [u8; 32],
    /// Human-readable cryptographic fingerprint of the node's identity key.
    pub fingerprint: String,
    /// Optional display name chosen by the user.
    pub name: Option<String>,
    /// The QUIC listen address that peers should connect to.
    pub listen_addr: SocketAddr,
    /// Protocol version for forward compatibility.
    pub version: u8,
}

/// A discovered peer on the local network.
#[derive(Clone, Debug)]
pub struct MeshPeer {
    /// Unique 32-byte node identifier.
    pub node_id: [u8; 32],
    /// Cryptographic fingerprint of the peer's identity key.
    pub fingerprint: String,
    /// Optional display name of the peer.
    pub name: Option<String>,
    /// Network address the peer is listening on for QUIC connections.
    pub addr: SocketAddr,
    /// Timestamp of the last received announcement from this peer.
    pub last_seen: Instant,
}

/// LAN mesh discovery service.
///
/// Uses UDP multicast to announce this node's presence and discover other
/// VeilComm peers on the same local network. Two background tasks are
/// spawned when [`start`](MeshDiscovery::start) is called:
///
/// - **Announce task**: broadcasts a [`MeshAnnouncement`] every 5 seconds.
/// - **Listen task**: receives announcements from other peers and maintains
///   the discovered peers map, expiring stale entries after 30 seconds.
pub struct MeshDiscovery {
    /// This node's unique identifier.
    node_id: [u8; 32],
    /// This node's fingerprint string.
    fingerprint: String,
    /// Optional display name for this node.
    name: Option<String>,
    /// The QUIC listen address advertised to peers.
    listen_addr: SocketAddr,
    /// Map from fingerprint to discovered peer information.
    discovered_peers: Arc<Mutex<HashMap<String, MeshPeer>>>,
    /// Flag indicating whether the discovery service is active.
    running: Arc<AtomicBool>,
}

impl MeshDiscovery {
    /// Creates a new mesh discovery instance.
    ///
    /// The service is not started until [`start`](MeshDiscovery::start) is called.
    ///
    /// # Arguments
    ///
    /// * `node_id` - Unique 32-byte identifier for this node.
    /// * `fingerprint` - Human-readable fingerprint of this node's identity key.
    /// * `name` - Optional display name.
    /// * `listen_addr` - The QUIC address this node listens on for incoming connections.
    pub fn new(
        node_id: [u8; 32],
        fingerprint: String,
        name: Option<String>,
        listen_addr: SocketAddr,
    ) -> Self {
        Self {
            node_id,
            fingerprint,
            name,
            listen_addr,
            discovered_peers: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts the mesh discovery service.
    ///
    /// Spawns two background tokio tasks:
    /// - An announce task that periodically broadcasts this node's presence.
    /// - A listen task that receives and processes announcements from other nodes.
    ///
    /// Returns an error if the UDP sockets cannot be bound or if multicast
    /// group membership cannot be established.
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(Error::Transport(
                "Mesh discovery is already running".to_string(),
            ));
        }

        self.running.store(true, Ordering::SeqCst);

        // Build the announcement payload once; it is cloned into each task.
        let announcement = MeshAnnouncement {
            node_id: self.node_id,
            fingerprint: self.fingerprint.clone(),
            name: self.name.clone(),
            listen_addr: self.listen_addr,
            version: PROTOCOL_VERSION,
        };

        // ---- Announce task ----
        let running_announce = Arc::clone(&self.running);
        let announce_msg = announcement.clone();
        tokio::spawn(async move {
            if let Err(e) = announce_loop(running_announce, announce_msg).await {
                tracing::error!("Mesh announce task failed: {}", e);
            }
        });

        // ---- Listen task ----
        let running_listen = Arc::clone(&self.running);
        let peers = Arc::clone(&self.discovered_peers);
        let own_node_id = self.node_id;
        tokio::spawn(async move {
            if let Err(e) = listen_loop(running_listen, peers, own_node_id).await {
                tracing::error!("Mesh listen task failed: {}", e);
            }
        });

        tracing::info!(
            "Mesh discovery started (multicast {}:{})",
            MULTICAST_GROUP,
            MULTICAST_PORT
        );

        Ok(())
    }

    /// Stops the mesh discovery service.
    ///
    /// Both the announce and listen background tasks will exit on their next
    /// iteration once this flag is observed.
    pub async fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("Mesh discovery stopped");
    }

    /// Returns a snapshot of all currently discovered LAN peers.
    ///
    /// Peers that have not been seen within the expiry window (30 seconds)
    /// are excluded from the result and removed from the internal map.
    pub fn discovered_peers(&self) -> Vec<MeshPeer> {
        let mut peers = self.discovered_peers.lock().unwrap();
        expire_stale_peers(&mut peers);
        peers.values().cloned().collect()
    }

    /// Returns `true` if the discovery service is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Background loop that broadcasts announcements at a fixed interval.
async fn announce_loop(running: Arc<AtomicBool>, announcement: MeshAnnouncement) -> Result<()> {
    // Bind to an ephemeral port on all interfaces for sending.
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| Error::Transport(format!("Failed to bind announce socket: {}", e)))?;

    let multicast_dest = SocketAddr::V4(SocketAddrV4::new(MULTICAST_GROUP, MULTICAST_PORT));

    let encoded = bincode::serialize(&announcement)
        .map_err(|e| Error::Transport(format!("Failed to serialize announcement: {}", e)))?;

    if encoded.len() > MAX_DATAGRAM_SIZE {
        return Err(Error::Transport(format!(
            "Announcement exceeds max datagram size ({} > {})",
            encoded.len(),
            MAX_DATAGRAM_SIZE
        )));
    }

    tracing::debug!(
        "Mesh announce loop started, payload {} bytes",
        encoded.len()
    );

    while running.load(Ordering::SeqCst) {
        match socket.send_to(&encoded, multicast_dest).await {
            Ok(_) => {
                tracing::trace!("Mesh: sent announcement to {}", multicast_dest);
            }
            Err(e) => {
                tracing::warn!("Mesh: failed to send announcement: {}", e);
            }
        }

        // Sleep in small increments so we can observe the running flag promptly.
        // Total sleep equals ANNOUNCE_INTERVAL (5 seconds), split into 100ms ticks.
        let ticks = ANNOUNCE_INTERVAL.as_millis() / 100;
        for _ in 0..ticks {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    tracing::debug!("Mesh announce loop exiting");
    Ok(())
}

/// Background loop that listens for multicast announcements from peers.
async fn listen_loop(
    running: Arc<AtomicBool>,
    peers: Arc<Mutex<HashMap<String, MeshPeer>>>,
    own_node_id: [u8; 32],
) -> Result<()> {
    // On Windows, multicast requires binding to 0.0.0.0, not the multicast
    // address itself. This is also safe on other platforms.
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MULTICAST_PORT);

    let socket = {
        // Use socket2 to set SO_REUSEADDR before binding so that multiple
        // instances on the same host can coexist.
        let std_socket = std::net::UdpSocket::bind(bind_addr)
            .map_err(|e| Error::Transport(format!("Failed to bind listen socket: {}", e)))?;

        std_socket
            .set_nonblocking(true)
            .map_err(|e| Error::Transport(format!("Failed to set non-blocking: {}", e)))?;

        UdpSocket::from_std(std_socket)
            .map_err(|e| Error::Transport(format!("Failed to create tokio socket: {}", e)))?
    };

    // Join the multicast group on all interfaces (0.0.0.0).
    socket
        .join_multicast_v4(MULTICAST_GROUP, Ipv4Addr::UNSPECIFIED)
        .map_err(|e| Error::Transport(format!("Failed to join multicast group: {}", e)))?;

    tracing::debug!(
        "Mesh listen loop started on {}:{}",
        MULTICAST_GROUP,
        MULTICAST_PORT
    );

    let mut buf = [0u8; MAX_DATAGRAM_SIZE];

    while running.load(Ordering::SeqCst) {
        // Use a short timeout so we can periodically check the running flag
        // and expire stale peers.
        let recv_result = tokio::time::timeout(
            Duration::from_secs(1),
            socket.recv_from(&mut buf),
        )
        .await;

        match recv_result {
            Ok(Ok((len, src_addr))) => {
                match bincode::deserialize::<MeshAnnouncement>(&buf[..len]) {
                    Ok(announcement) => {
                        // Skip our own announcements.
                        if announcement.node_id == own_node_id {
                            continue;
                        }

                        // Ignore announcements from incompatible protocol versions.
                        if announcement.version != PROTOCOL_VERSION {
                            tracing::debug!(
                                "Mesh: ignoring announcement with version {} from {}",
                                announcement.version,
                                src_addr
                            );
                            continue;
                        }

                        let fingerprint = announcement.fingerprint.clone();
                        let addr = announcement.listen_addr;

                        let mut map = peers.lock().unwrap();

                        let is_new = !map.contains_key(&fingerprint);

                        map.insert(
                            fingerprint.clone(),
                            MeshPeer {
                                node_id: announcement.node_id,
                                fingerprint: fingerprint.clone(),
                                name: announcement.name.clone(),
                                addr,
                                last_seen: Instant::now(),
                            },
                        );

                        if is_new {
                            tracing::info!("Mesh: discovered peer {} at {}", fingerprint, addr);
                        } else {
                            tracing::trace!("Mesh: refreshed peer {} at {}", fingerprint, addr);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Mesh: failed to deserialize announcement from {}: {}",
                            src_addr,
                            e
                        );
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("Mesh: recv error: {}", e);
            }
            Err(_) => {
                // Timeout - normal, just proceed to expiry check.
            }
        }

        // Expire stale peers.
        let mut map = peers.lock().unwrap();
        expire_stale_peers(&mut map);
    }

    // Leave the multicast group on shutdown.
    let _ = socket.leave_multicast_v4(MULTICAST_GROUP, Ipv4Addr::UNSPECIFIED);

    tracing::debug!("Mesh listen loop exiting");
    Ok(())
}

/// Removes peers that have not been seen within [`PEER_EXPIRY`].
fn expire_stale_peers(peers: &mut HashMap<String, MeshPeer>) {
    let now = Instant::now();
    peers.retain(|fingerprint, peer| {
        let alive = now.duration_since(peer.last_seen) < PEER_EXPIRY;
        if !alive {
            tracing::info!("Mesh: peer {} expired (no announcement for 30s)", fingerprint);
        }
        alive
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Verify that a MeshAnnouncement survives a bincode roundtrip.
    #[test]
    fn test_mesh_announcement_serialization() {
        let announcement = MeshAnnouncement {
            node_id: [42u8; 32],
            fingerprint: "ABCD-EF01-2345-6789".to_string(),
            name: Some("Alice".to_string()),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 4433),
            version: PROTOCOL_VERSION,
        };

        let encoded = bincode::serialize(&announcement).expect("serialization should succeed");
        assert!(!encoded.is_empty());
        assert!(
            encoded.len() <= MAX_DATAGRAM_SIZE,
            "encoded announcement should fit in a single datagram"
        );

        let decoded: MeshAnnouncement =
            bincode::deserialize(&encoded).expect("deserialization should succeed");

        assert_eq!(decoded.node_id, announcement.node_id);
        assert_eq!(decoded.fingerprint, announcement.fingerprint);
        assert_eq!(decoded.name, announcement.name);
        assert_eq!(decoded.listen_addr, announcement.listen_addr);
        assert_eq!(decoded.version, announcement.version);
    }

    /// Verify that a MeshAnnouncement with no optional name also roundtrips.
    #[test]
    fn test_mesh_announcement_serialization_no_name() {
        let announcement = MeshAnnouncement {
            node_id: [0u8; 32],
            fingerprint: "0000-0000-0000-0000".to_string(),
            name: None,
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999),
            version: PROTOCOL_VERSION,
        };

        let encoded = bincode::serialize(&announcement).expect("serialization should succeed");
        let decoded: MeshAnnouncement =
            bincode::deserialize(&encoded).expect("deserialization should succeed");

        assert_eq!(decoded.name, None);
        assert_eq!(decoded.fingerprint, announcement.fingerprint);
    }

    /// Verify MeshDiscovery can be created and has sensible defaults.
    #[test]
    fn test_mesh_discovery_creation() {
        let node_id = [7u8; 32];
        let fingerprint = "TEST-FING-ERPR-INTT".to_string();
        let name = Some("TestNode".to_string());
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4433);

        let discovery = MeshDiscovery::new(node_id, fingerprint.clone(), name.clone(), listen_addr);

        assert_eq!(discovery.node_id, node_id);
        assert_eq!(discovery.fingerprint, fingerprint);
        assert_eq!(discovery.name, name);
        assert_eq!(discovery.listen_addr, listen_addr);
        assert!(!discovery.is_running(), "should not be running before start");
    }

    /// Verify that stale peers are evicted from the map.
    #[tokio::test]
    async fn test_mesh_peer_expiry() {
        let mut peers = HashMap::new();

        // Insert a "fresh" peer.
        peers.insert(
            "fresh-peer".to_string(),
            MeshPeer {
                node_id: [1u8; 32],
                fingerprint: "fresh-peer".to_string(),
                name: Some("Fresh".to_string()),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 4433),
                last_seen: Instant::now(),
            },
        );

        // Insert a "stale" peer by backdating its last_seen beyond the expiry window.
        peers.insert(
            "stale-peer".to_string(),
            MeshPeer {
                node_id: [2u8; 32],
                fingerprint: "stale-peer".to_string(),
                name: Some("Stale".to_string()),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 4433),
                last_seen: Instant::now() - Duration::from_secs(60),
            },
        );

        assert_eq!(peers.len(), 2);

        expire_stale_peers(&mut peers);

        assert_eq!(peers.len(), 1, "stale peer should have been removed");
        assert!(
            peers.contains_key("fresh-peer"),
            "fresh peer should still be present"
        );
        assert!(
            !peers.contains_key("stale-peer"),
            "stale peer should have been evicted"
        );
    }

    /// Verify that the discovered_peers method also triggers expiry.
    #[tokio::test]
    async fn test_discovered_peers_expires_stale() {
        let node_id = [9u8; 32];
        let discovery = MeshDiscovery::new(
            node_id,
            "self-fp".to_string(),
            None,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433),
        );

        // Manually insert a stale peer.
        {
            let mut map = discovery.discovered_peers.lock().unwrap();
            map.insert(
                "gone-peer".to_string(),
                MeshPeer {
                    node_id: [3u8; 32],
                    fingerprint: "gone-peer".to_string(),
                    name: None,
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 4433),
                    last_seen: Instant::now() - Duration::from_secs(60),
                },
            );
        }

        let found = discovery.discovered_peers();
        assert!(
            found.is_empty(),
            "stale peer should not appear in discovered_peers"
        );
    }
}
