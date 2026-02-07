<p align="center">
  <img src="https://img.shields.io/badge/rust-2021-orange?style=flat-square&logo=rust" alt="Rust 2021">
  <img src="https://img.shields.io/badge/crypto-post--quantum-blueviolet?style=flat-square" alt="Post-Quantum">
  <img src="https://img.shields.io/badge/transport-QUIC-00e5ff?style=flat-square" alt="QUIC">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/tests-80%20passing-brightgreen?style=flat-square" alt="Tests">
</p>

# VeilComm

**Post-quantum encrypted peer-to-peer messaging.**

VeilComm is a from-scratch Rust implementation of a secure P2P chat system that combines classical elliptic-curve cryptography with Kyber-1024 lattice-based post-quantum protection. Every message is end-to-end encrypted with forward secrecy via the Double Ratchet protocol, keys are exchanged through a hybrid PQXDH handshake, and peers communicate directly over QUIC with Kademlia DHT discovery.

```
  Alice                                          Bob
    |                                              |
    |──── PQXDH (X25519 + Kyber-1024 KEM) ───────>|
    |<──── Shared Secret (BLAKE2s combined) ───────|
    |                                              |
    |──── Double Ratchet (ChaCha20-Poly1305) ─────>|
    |<──── Forward-Secret Messages ────────────────|
    |                                              |
    └──────────── QUIC / Kademlia DHT ─────────────┘
```

---

## Features

| | VeilComm |
|---|---|
| **End-to-End Encryption** | ChaCha20-Poly1305 AEAD per message |
| **Forward Secrecy** | Double Ratchet - unique key per message |
| **Post-Quantum** | Hybrid X25519 + Kyber-1024 KEM |
| **Key Exchange** | PQXDH (post-quantum Extended Triple Diffie-Hellman) |
| **Transport** | QUIC with TLS 1.3 / TCP+TLS via Tor |
| **Metadata Protection** | Tor onion routing (optional) |
| **Peer Discovery** | Kademlia DHT with iterative lookup |
| **NAT Traversal** | STUN for public address discovery |
| **Key Storage** | Argon2id-encrypted keystore (64 MiB, 3 iterations) |
| **Identity** | Ed25519 signatures + X25519 DH + Kyber-1024 KEM |
| **Interface** | Web GUI (glassmorphism) + CLI |

## Tor Setup (Optional)

VeilComm can optionally route all peer connections through Tor to hide IP addresses:

1. **Install Tor**: Download from [torproject.org](https://www.torproject.org/) or install via package manager
2. **Configure a hidden service** in your `torrc`:
   ```
   HiddenServiceDir /var/lib/tor/veilcomm/
   HiddenServicePort 9051 127.0.0.1:9051
   ```
3. **Start Tor** and note the generated `.onion` address from `hostname` file
4. **Start VeilComm** with Tor enabled in the GUI Network panel:
   - Check "Tor Routing"
   - Enter SOCKS5 proxy address (default `127.0.0.1:9050`)
   - Enter Tor listen port (must match `torrc`, default `9051`)
   - Enter your `.onion:port` address
5. Share your onion address with contacts for metadata-protected messaging

## Quick Start

```bash
# Build
cargo build --release

# Run the web GUI (opens browser to localhost:3000)
cargo run --release -p veilcomm-gui

# Or use the CLI
cargo run --release -p veilcomm-cli -- --help
```

### Web GUI

The GUI serves a glassmorphism-styled frontend on `localhost:3000`. Create an identity, manage contacts, and chat -- all from your browser.

```bash
cargo run -p veilcomm-gui
# Opens http://127.0.0.1:3000 automatically
```

### CLI

```bash
# Create a new identity
veilcomm init --name "Alice"

# Show your identity fingerprint
veilcomm identity

# Export your key bundle for sharing
veilcomm export

# Manage contacts
veilcomm contact add <fingerprint> --name "Bob"
veilcomm contact list
veilcomm contact verify <fingerprint>
veilcomm contact remove <fingerprint>

# Messaging (requires active session)
veilcomm send <contact> "Hello, Bob!"
veilcomm read <contact>

# Account management
veilcomm change-password
```

## Architecture

```
veilcomm/
├── crates/
│   ├── veilcomm-core/       # Cryptographic primitives & protocol
│   │   ├── crypto/
│   │   │   ├── keys.rs      # Ed25519 + X25519 + Kyber-1024 identity keys
│   │   │   ├── x3dh.rs      # Hybrid PQXDH key exchange
│   │   │   ├── ratchet.rs   # Double Ratchet with header encryption
│   │   │   ├── aead.rs      # ChaCha20-Poly1305 AEAD
│   │   │   ├── pq.rs        # Kyber-1024 KEM wrapper
│   │   │   └── kdf.rs       # HKDF-SHA256 + BLAKE2b key derivation
│   │   └── protocol/
│   │       ├── session.rs    # Encrypted session management
│   │       └── message.rs    # Message types & serialization
│   │
│   ├── veilcomm-network/    # P2P networking
│   │   ├── transport/
│   │   │   ├── quic.rs      # QUIC transport (quinn)
│   │   │   └── tor.rs       # Tor transport (TCP+TLS via SOCKS5)
│   │   ├── dht/             # Kademlia DHT (20-bucket, k=20)
│   │   ├── service.rs       # Network service orchestrator
│   │   ├── protocol.rs      # Wire protocol (bincode-serialized)
│   │   ├── peer.rs          # Connection manager + peer lifecycle
│   │   └── nat.rs           # STUN NAT traversal
│   │
│   ├── veilcomm-storage/    # Persistent storage
│   │   ├── keystore.rs      # Argon2id-encrypted identity keystore
│   │   └── database.rs      # SQLite (contacts, messages, sessions)
│   │
│   ├── veilcomm-app/        # Application logic
│   │   └── client.rs        # VeilCommClient API
│   │
│   ├── veilcomm-cli/        # Terminal interface
│   └── veilcomm-gui/        # Web GUI (axum + embedded HTML)
│       ├── src/main.rs       # REST API server
│       └── static/index.html # Glassmorphism frontend
```

## Cryptographic Design

### Key Hierarchy

```
Identity Key (long-term, generated once)
├── Ed25519 SigningKey ─── authentication & signatures
├── X25519 StaticSecret ── classical Diffie-Hellman
├── Kyber-1024 KeyPair ─── post-quantum KEM
│
├── Signed Pre-Key (rotatable)
│   └── X25519 + Ed25519 signature
│
└── One-Time Pre-Keys (consumed on use, batch of 100)
    └── X25519
```

### PQXDH Key Exchange

VeilComm extends the X3DH protocol with Kyber-1024 to create a hybrid post-quantum key exchange:

1. Classical X3DH produces a shared secret from 3-4 DH operations
2. Kyber-1024 KEM produces a post-quantum shared secret via encapsulation
3. Both secrets are combined via `BLAKE2s(classical || pq || "VeilComm_PQ_v1")` into a single 32-byte key

This means the session is secure if **either** X25519 or Kyber-1024 remains unbroken.

### Double Ratchet

Each message gets a unique encryption key through the Double Ratchet:

- **DH Ratchet**: New X25519 ephemeral per direction change
- **Chain Ratchet**: BLAKE2b KDF chain per message
- **Message Key**: Derived from chain, used once, then discarded
- **Skipped Keys**: Cached up to 2000 total for out-of-order delivery
- **AEAD**: ChaCha20-Poly1305 with associated data binding

### Peer Authentication

QUIC connections are authenticated at the application layer:

1. Initiator generates a random 32-byte nonce
2. Challenge = `node_id || addr || nonce`
3. Both sides sign the challenge with their Ed25519 identity key
4. Signatures are verified before the connection is accepted

### Storage Security

- Identity keys encrypted with ChaCha20-Poly1305
- Encryption key derived from password via Argon2id (64 MiB, 3 iterations, 4 lanes)
- All cryptographic keys zeroized on drop (including Ed25519, X25519, Kyber-1024)
- SQLite database for contacts, messages, and session state

## Testing

```bash
# Run all 80 tests
cargo test --all

# Run tests for a specific crate
cargo test -p veilcomm-core
cargo test -p veilcomm-network
cargo test -p veilcomm-storage
cargo test -p veilcomm-app

# Lint
cargo clippy --all
```

### Test Coverage

| Crate | Tests | Coverage |
|-------|-------|----------|
| `veilcomm-core` | 51 | AEAD, KDF, keys, X3DH, Double Ratchet, PQ, sessions |
| `veilcomm-network` | 16 | QUIC transport, DHT, connection manager, protocol, STUN, NAT |
| `veilcomm-storage` | 10 | Keystore CRUD, password change, database CRUD, sessions |
| `veilcomm-app` | 3 | Init/unlock, contacts, wrong password rejection |

## Wire Protocol

Peers communicate via length-prefixed bincode-serialized messages over QUIC bidirectional streams:

| Message | Purpose |
|---------|---------|
| `Handshake` / `HandshakeAck` | Identity verification with Ed25519 + nonce |
| `EncryptedMessage` / `MessageAck` | End-to-end encrypted payload delivery |
| `FindNode` / `FindNodeResponse` | Kademlia iterative lookup |
| `StoreRecord` / `GetRecord` | DHT record storage (pre-key bundles, etc.) |
| `RequestPreKeyBundle` / `PreKeyBundleResponse` | Pre-key exchange for X3DH |
| `Ping` / `Pong` | Liveness check |

## Comparison with Existing Messengers

### Where VeilComm stands out

**Post-Quantum Cryptography**

| App | PQ Key Exchange | Approach |
|-----|----------------|----------|
| **VeilComm** | Yes | Hybrid X25519 + Kyber-1024 from day one |
| Signal | Yes | Added PQXDH (Kyber-1024) in 2023, retrofitted |
| WhatsApp | No | Signal Protocol without PQ |
| Telegram | No | MTProto 2.0, classical only |
| Tox | No | NaCl/libsodium, classical only |
| Session | No | Signal Protocol fork, classical only |
| Briar | No | Bramble protocol, classical only |
| Matrix/Element | Experimental | Vodozemac, PQ not production-ready |

VeilComm and Signal are currently the only messengers with production-grade hybrid post-quantum key exchange. VeilComm has it built into the foundation rather than added after the fact.

**True Serverless P2P**

| App | Architecture | Metadata Exposure |
|-----|-------------|-------------------|
| **VeilComm** | Direct P2P (QUIC + DHT), optional Tor | No server-side metadata, optional IP hiding |
| Signal | Centralized (AWS) | Server sees who talks to whom, when |
| WhatsApp | Centralized (Meta) | Server sees social graph + timing |
| Telegram | Centralized | Server sees everything in non-secret chats |
| Tox | P2P (DHT) | Similar to VeilComm |
| Session | Decentralized (onion-routed) | Minimal, 3-hop routing |
| Briar | P2P (Tor/WiFi/BT) | Minimal |
| Matrix | Federated servers | Homeserver sees metadata |

No registration, no phone number, no servers to subpoena. Your identity is a cryptographic keypair, period.

**Auditability**

~12,000 lines of Rust. The entire cryptographic stack can be reviewed in an afternoon. Signal's codebase spans hundreds of thousands of lines across Java, Swift, and TypeScript. Smaller attack surface, easier to verify.

### Where VeilComm falls short (honest assessment)

**No professional security audit.** This is the biggest gap. Signal's protocol has been formally verified by academic researchers and audited by firms like NCC Group. VeilComm has not. "The code compiles and tests pass" is not the same as "this is secure against a nation-state adversary."

**Metadata protection is optional.** By default, direct QUIC connections expose both peers' IP addresses. Tor onion routing can be enabled to hide IPs, but it is opt-in and requires running a Tor daemon. Signal has sealed sender and private contact discovery built-in. Session has mandatory onion routing. Briar routes through Tor by default.

**No offline messaging.** Both peers must be online simultaneously. If Bob is offline, Alice's message goes nowhere. Signal, WhatsApp, Session, and Matrix all queue messages for later delivery. This is a fundamental limitation of pure P2P without relay infrastructure.

**No group chat.** Signal supports up to 1,000 members with Sender Keys. VeilComm is 1:1 only.

**No mobile apps.** Desktop only, requires building from source.

**Unencrypted message database.** The identity keystore is encrypted with Argon2id + ChaCha20-Poly1305, but the SQLite database storing messages and contacts is not encrypted at rest. Signal uses SQLCipher. This is a known gap.

### Summary

| Feature | VeilComm | Signal | Tox | Session | Briar |
|---------|----------|--------|-----|---------|-------|
| Post-Quantum | **Hybrid PQ** | **Hybrid PQ** | None | None | None |
| Forward Secrecy | **Double Ratchet** | **Double Ratchet** | None | Partial | **Yes** |
| Serverless P2P | **Yes** | No | **Yes** | Partial | **Yes** |
| Metadata Protection | Tor optional | Good | Poor | **Strong** | **Strong** |
| Offline Messaging | None | **Yes** | None | **Yes** | Partial |
| Group Chat | None | **Yes** | **Yes** | **Yes** | **Yes** |
| Security Audits | None | **Extensive** | Some | Some | **Yes** |
| Mobile Apps | None | **Yes** | Partial | **Yes** | **Yes** |
| Codebase Size | **~12K LOC** | ~500K+ LOC | ~100K LOC | ~200K LOC | ~100K LOC |
| Language | **Rust** | Java/Swift/TS | C | Kotlin/Swift | Java |

**VeilComm is a strong cryptographic foundation, not a production messenger.** It demonstrates that post-quantum P2P messaging can be built from scratch in Rust with a small, auditable codebase. It is not yet suitable for high-stakes communication -- use Signal for that until VeilComm matures.

## Roadmap

- [x] Hybrid PQXDH key exchange (X25519 + Kyber-1024)
- [x] Double Ratchet with forward secrecy
- [x] QUIC P2P transport with authenticated handshake
- [x] Kademlia DHT peer discovery
- [x] STUN NAT traversal
- [x] Web GUI with glassmorphism design
- [x] CLI with full identity/contact/message management
- [x] Tor integration for metadata protection
- [ ] Offline messaging via DHT relay
- [ ] Group chat (Sender Keys)
- [ ] File transfer
- [ ] Mobile clients

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
