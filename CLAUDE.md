# VeilComm Project Guidelines

## Overview
VeilComm is a secure P2P encrypted chat application in Rust with hybrid post-quantum cryptographic protection (X25519 + Kyber-1024).

## Tech Stack
- **Language**: Rust 2021 edition
- **Crypto**: x25519-dalek, ed25519-dalek, pqcrypto-kyber, chacha20poly1305
- **Storage**: rusqlite with Argon2-encrypted keystore
- **Networking**: QUIC (quinn) with Kademlia DHT, STUN NAT traversal, Tor onion routing (TCP+TLS via tokio-socks/tokio-rustls)
- **CLI**: clap
- **GUI**: axum web server serving embedded HTML frontend
- **Async**: tokio

## Project Structure
```
veilcomm/
├── crates/
│   ├── veilcomm-core/      # Crypto primitives & protocol
│   ├── veilcomm-network/   # P2P (QUIC), DHT, NAT traversal
│   ├── veilcomm-storage/   # Encrypted database & keystore
│   ├── veilcomm-app/       # Application logic & client API
│   ├── veilcomm-cli/       # CLI binary
│   └── veilcomm-gui/       # Web GUI binary (axum + embedded HTML)
```

## Development Guidelines

### Code Style
- Follow Rust idioms
- Use `Result<T, Error>` for fallible operations
- Implement `Zeroize` for sensitive data
- Document public APIs with rustdoc

### Security Requirements
- All cryptographic keys must be zeroized on drop
- Password-derived keys use Argon2id
- No plaintext storage of secrets
- Constant-time comparisons for sensitive data

### Testing
- Unit tests in each module
- Property-based tests for crypto (proptest)
- Integration tests for session establishment

## Common Tasks

```bash
# Build
cargo build --release

# Test all
cargo test --all

# Run CLI
cargo run -p veilcomm-cli -- --help

# Run GUI
cargo run -p veilcomm-gui

# Check for issues
cargo clippy --all
```

## Important Notes
- Hybrid PQXDH is fully implemented: X3DH key exchange combines X25519 with Kyber-1024 KEM
- Network layer is implemented: QUIC transport, Kademlia DHT, peer handshake, message relay
- NAT traversal uses STUN for public address discovery
- Tor integration is implemented: optional TCP+TLS transport via SOCKS5 proxy for .onion hidden service connections
- GUI serves a glassmorphism frontend on localhost:3000 via axum
