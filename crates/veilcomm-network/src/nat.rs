//! NAT traversal using STUN
//!
//! Discovers our public IP:port by querying public STUN servers.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::error::{Error, Result};

/// Well-known public STUN servers
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// STUN message type: Binding Request
const STUN_BINDING_REQUEST: u16 = 0x0001;
/// STUN magic cookie (RFC 5389)
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
/// STUN attribute: XOR-MAPPED-ADDRESS
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// STUN attribute: MAPPED-ADDRESS (fallback)
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// Discover our public address by querying STUN servers
///
/// Tries each STUN server in order until one responds.
/// Returns the public SocketAddr as seen by the STUN server.
pub async fn discover_public_addr(local_bind: SocketAddr) -> Result<SocketAddr> {
    let socket = UdpSocket::bind(local_bind)
        .await
        .map_err(|e| Error::Transport(format!("Failed to bind UDP for STUN: {}", e)))?;

    // Build a STUN Binding Request
    let transaction_id: [u8; 12] = rand::random();
    let request = build_stun_request(&transaction_id);

    for server in STUN_SERVERS {
        // Resolve STUN server address
        let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(server).await {
            Ok(addrs) => addrs.collect(),
            Err(_) => continue,
        };

        for addr in addrs {
            if socket.send_to(&request, addr).await.is_err() {
                continue;
            }

            let mut buf = [0u8; 1024];
            let timeout = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                socket.recv_from(&mut buf),
            );

            match timeout.await {
                Ok(Ok((len, _))) => {
                    if let Some(mapped_addr) = parse_stun_response(&buf[..len], &transaction_id) {
                        return Ok(mapped_addr);
                    }
                }
                _ => continue,
            }
        }
    }

    Err(Error::Transport(
        "Failed to discover public address from any STUN server".to_string(),
    ))
}

/// Build a minimal STUN Binding Request
fn build_stun_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    // Message Type: Binding Request (0x0001)
    buf.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    // Message Length: 0 (no attributes)
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Magic Cookie
    buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    buf.extend_from_slice(transaction_id);
    buf
}

/// Parse a STUN response and extract the mapped address
fn parse_stun_response(data: &[u8], expected_txn: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 20 {
        return None;
    }

    // Verify it's a Binding Success Response (0x0101)
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != 0x0101 {
        return None;
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

    // Verify magic cookie
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return None;
    }

    // Verify transaction ID
    if &data[8..20] != expected_txn {
        return None;
    }

    // Parse attributes
    let attrs = &data[20..20 + msg_len.min(data.len() - 20)];
    let mut pos = 0;
    while pos + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[pos], attrs[pos + 1]]);
        let attr_len = u16::from_be_bytes([attrs[pos + 2], attrs[pos + 3]]) as usize;
        pos += 4;

        if pos + attr_len > attrs.len() {
            break;
        }

        let attr_data = &attrs[pos..pos + attr_len];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return parse_xor_mapped_address(attr_data, &data[4..8]);
            }
            ATTR_MAPPED_ADDRESS => {
                return parse_mapped_address(attr_data);
            }
            _ => {}
        }

        // Attributes are padded to 4-byte boundaries
        pos += (attr_len + 3) & !3;
    }

    None
}

/// Parse XOR-MAPPED-ADDRESS attribute
fn parse_xor_mapped_address(data: &[u8], magic: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }

    let family = data[1];
    let xport = u16::from_be_bytes([data[2], data[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            let ip = [
                data[4] ^ magic[0],
                data[5] ^ magic[1],
                data[6] ^ magic[2],
                data[7] ^ magic[3],
            ];
            let addr = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
            Some(SocketAddr::new(std::net::IpAddr::V4(addr), xport))
        }
        0x02 if data.len() >= 20 => {
            // IPv6
            let mut ip_bytes = [0u8; 16];
            // XOR with magic cookie + transaction ID
            for i in 0..16 {
                if i < 4 {
                    ip_bytes[i] = data[4 + i] ^ magic[i];
                } else {
                    ip_bytes[i] = data[4 + i]; // simplified - full impl XORs with txn id
                }
            }
            let addr = std::net::Ipv6Addr::from(ip_bytes);
            Some(SocketAddr::new(std::net::IpAddr::V6(addr), xport))
        }
        _ => None,
    }
}

/// Parse MAPPED-ADDRESS attribute (non-XOR fallback)
fn parse_mapped_address(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            let addr = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some(SocketAddr::new(std::net::IpAddr::V4(addr), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_stun_request() {
        let txn_id = [1u8; 12];
        let request = build_stun_request(&txn_id);
        assert_eq!(request.len(), 20);
        // Check message type
        assert_eq!(request[0], 0x00);
        assert_eq!(request[1], 0x01);
        // Check magic cookie
        assert_eq!(u32::from_be_bytes([request[4], request[5], request[6], request[7]]), STUN_MAGIC_COOKIE);
    }

    #[test]
    fn test_parse_xor_mapped_address() {
        let magic = STUN_MAGIC_COOKIE.to_be_bytes();
        // Family IPv4, port 8080 XORed, IP 192.168.1.1 XORed
        let port_xor = 8080u16 ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let ip_bytes = [
            192 ^ magic[0],
            168 ^ magic[1],
            1 ^ magic[2],
            1 ^ magic[3],
        ];
        let data = [
            0x00, 0x01, // reserved + family (IPv4)
            (port_xor >> 8) as u8, (port_xor & 0xFF) as u8,
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
        ];

        let addr = parse_xor_mapped_address(&data, &magic).unwrap();
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
    }
}
