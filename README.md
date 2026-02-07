<p align="center">
  <img src="https://img.shields.io/badge/rust-2021-orange?style=flat-square&logo=rust" alt="Rust 2021">
  <img src="https://img.shields.io/badge/crypto-post--quantum-blueviolet?style=flat-square" alt="Post-Quantum">
  <img src="https://img.shields.io/badge/transport-QUIC-00e5ff?style=flat-square" alt="QUIC">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/tests-107%20passing-brightgreen?style=flat-square" alt="Tests">
</p>

# VeilComm

**Post-quantum encrypted peer-to-peer messaging with offline delivery and group chat.**

VeilComm is a from-scratch Rust implementation of a secure P2P chat system that combines classical elliptic-curve cryptography with Kyber-1024 lattice-based post-quantum protection. Every message is end-to-end encrypted with forward secrecy via the Double Ratchet protocol, keys are exchanged through a hybrid PQXDH handshake, and peers communicate directly over QUIC with Kademlia DHT discovery. Messages to offline peers are stored in the DHT for later delivery, and group chats use Signal-style Sender Keys for efficient multi-party encryption.

```
  Alice                                          Bob (offline)
    |                                              |
    |──── PQXDH (X25519 + Kyber-1024 KEM) ───────>|
    |<──── Shared Secret (BLAKE2s combined) ───────|
    |                                              |
    |──── Double Ratchet (ChaCha20-Poly1305) ─────>|
    |──── Store in DHT (offline delivery) ────────>|  DHT
    |                                              |   |
    |              Bob comes online ───────────────|<──┘
    |<──── Forward-Secret Messages ────────────────|
    |                                              |
    └──────────── QUIC / Kademlia DHT ─────────────┘

  Group Chat (Sender Keys)
    Alice ──┐
    Bob   ──┼── Encrypt once, deliver to all members
    Carol ──┘   ChaCha20-Poly1305 + Ed25519 signatures
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
| **Offline Messaging** | DHT store-and-forward with delivery status tracking |
| **Group Chat** | Sender Keys (up to 100 members) with chain ratchet |
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

The GUI serves a glassmorphism-styled frontend on `localhost:3000`. Create an identity, manage contacts, chat 1:1 or in groups, and monitor your P2P network -- all from your browser.

```bash
cargo run -p veilcomm-gui
# Opens http://127.0.0.1:3000 automatically
```

Features include:
- **Delivery status indicators**: clock (pending), cloud (queued in DHT), single check (sent), double check (delivered/read)
- **Group chat**: create groups from your contacts, per-sender colored message labels, group info panel with member management
- **Offline message polling**: automatically checks for queued messages every 30 seconds

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
│   │   │   ├── sender_key.rs# Sender Keys for group chat encryption
│   │   │   ├── aead.rs      # ChaCha20-Poly1305 AEAD
│   │   │   ├── pq.rs        # Kyber-1024 KEM wrapper
│   │   │   └── kdf.rs       # HKDF-SHA256 + BLAKE2b key derivation
│   │   └── protocol/
│   │       ├── session.rs    # Encrypted session management
│   │       ├── message.rs    # Message types & serialization
│   │       └── group.rs      # Group protocol types & actions
│   │
│   ├── veilcomm-network/    # P2P networking
│   │   ├── transport/
│   │   │   ├── quic.rs      # QUIC transport (quinn)
│   │   │   └── tor.rs       # Tor transport (TCP+TLS via SOCKS5)
│   │   ├── dht/             # Kademlia DHT (20-bucket, k=20)
│   │   ├── service.rs       # Network service + offline messaging
│   │   ├── protocol.rs      # Wire protocol (bincode-serialized)
│   │   ├── peer.rs          # Connection manager + peer lifecycle
│   │   └── nat.rs           # STUN NAT traversal
│   │
│   ├── veilcomm-storage/    # Persistent storage
│   │   ├── keystore.rs      # Argon2id-encrypted identity keystore
│   │   └── database.rs      # SQLite (contacts, messages, sessions, groups, sender keys)
│   │
│   ├── veilcomm-app/        # Application logic
│   │   └── client.rs        # VeilCommClient API
│   │
│   ├── veilcomm-cli/        # Terminal interface
│   └── veilcomm-gui/        # Web GUI (axum + embedded HTML)
│       ├── src/main.rs       # REST API server (30+ endpoints)
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
├── One-Time Pre-Keys (consumed on use, batch of 100)
│   └── X25519
│
└── Sender Keys (per group, chain-ratcheted)
    ├── Chain Key ─── symmetric key, ratcheted per message via BLAKE2b
    └── Ed25519 SigningKey ─── message authentication
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

### Sender Keys (Group Chat)

Group messages use Signal-style Sender Keys for efficient multi-party encryption:

- Each member generates a **Sender Key** (chain key + Ed25519 signing key) per group
- Sender Keys are distributed to all members via existing pairwise sessions
- Messages are encrypted **once** with ChaCha20-Poly1305, then sent to all members
- Each message is signed with Ed25519 for authentication
- The chain key is ratcheted forward via BLAKE2b after each message (forward secrecy)
- Out-of-order delivery supported via skipped key caching (up to 256 keys)
- Member removal triggers a re-key: all remaining members generate new Sender Keys

### Offline Messaging

When a peer is offline, messages are stored in the Kademlia DHT for later retrieval:

1. Sender encrypts the message normally via Double Ratchet
2. Encrypted payload is stored in the DHT under the recipient's fingerprint
3. Payload is replicated to the 3 closest DHT nodes for redundancy
4. When the recipient comes online, they query the DHT for pending messages
5. Messages are decrypted with the existing session and acknowledged (deleted from DHT)
6. Messages expire after 7 days; per-key limit of 50 offline messages

Delivery status is tracked per message: `pending` -> `sent_to_dht` -> `delivered`.

### Peer Authentication

QUIC connections are authenticated at the application layer:

1. Initiator generates a random 32-byte nonce
2. Challenge = `node_id || addr || nonce`
3. Both sides sign the challenge with their Ed25519 identity key
4. Signatures are verified before the connection is accepted

### Storage Security

- Identity keys encrypted with ChaCha20-Poly1305
- Encryption key derived from password via Argon2id (64 MiB, 3 iterations, 4 lanes)
- All cryptographic keys zeroized on drop (including Ed25519, X25519, Kyber-1024, Sender Keys)
- SQLite database for contacts, messages, sessions, groups, and sender keys

## Testing

```bash
# Run all 107 tests
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
| `veilcomm-core` | 61 | AEAD, KDF, keys, X3DH, Double Ratchet, PQ, sessions, Sender Keys, group protocol |
| `veilcomm-network` | 28 | QUIC transport, DHT, offline messages, connection manager, protocol, STUN, NAT, Tor |
| `veilcomm-storage` | 15 | Keystore CRUD, password change, database CRUD, sessions, groups, members, sender keys, delivery status |
| `veilcomm-app` | 3 | Init/unlock, contacts, wrong password rejection |

## Wire Protocol

Peers communicate via length-prefixed bincode-serialized messages over QUIC bidirectional streams:

| Message | Purpose |
|---------|---------|
| `Handshake` / `HandshakeAck` | Identity verification with Ed25519 + nonce |
| `EncryptedMessage` / `MessageAck` | End-to-end encrypted payload delivery |
| `FindNode` / `FindNodeResponse` | Kademlia iterative lookup |
| `StoreRecord` / `GetRecord` | DHT record storage (pre-key bundles, offline messages) |
| `RequestPreKeyBundle` / `PreKeyBundleResponse` | Pre-key exchange for X3DH |
| `GetOfflineMessages` / `GetOfflineMessagesResponse` | Retrieve queued offline messages |
| `AckOfflineMessages` / `AckOfflineMessagesResponse` | Acknowledge and delete offline messages |
| `GroupMessage` / `GroupMessageAck` | Sender Key encrypted group message delivery |
| `SenderKeyDistribution` | Distribute Sender Keys to group members |
| `GroupManagement` | Group create, add/remove member, leave, rename |
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

~14,000 lines of Rust. The entire cryptographic stack can be reviewed in an afternoon. Signal's codebase spans hundreds of thousands of lines across Java, Swift, and TypeScript. Smaller attack surface, easier to verify.

### Where VeilComm falls short (honest assessment)

**No professional security audit.** This is the biggest gap. Signal's protocol has been formally verified by academic researchers and audited by firms like NCC Group. VeilComm has not. "The code compiles and tests pass" is not the same as "this is secure against a nation-state adversary."

**Metadata protection is optional.** By default, direct QUIC connections expose both peers' IP addresses. Tor onion routing can be enabled to hide IPs, but it is opt-in and requires running a Tor daemon. Signal has sealed sender and private contact discovery built-in. Session has mandatory onion routing. Briar routes through Tor by default.

**No mobile apps.** Desktop only, requires building from source.


### Summary

| Feature | VeilComm | Signal | Tox | Session | Briar |
|---------|----------|--------|-----|---------|-------|
| Post-Quantum | **Hybrid PQ** | **Hybrid PQ** | None | None | None |
| Forward Secrecy | **Double Ratchet** | **Double Ratchet** | None | Partial | **Yes** |
| Serverless P2P | **Yes** | No | **Yes** | Partial | **Yes** |
| Metadata Protection | Tor optional | Good | Poor | **Strong** | **Strong** |
| Offline Messaging | **DHT relay** | **Yes** | None | **Yes** | Partial |
| Group Chat | **Sender Keys** | **Yes** | **Yes** | **Yes** | **Yes** |
| Security Audits | None | **Extensive** | Some | Some | **Yes** |
| Mobile Apps | None | **Yes** | Partial | **Yes** | **Yes** |
| Codebase Size | **~14K LOC** | ~500K+ LOC | ~100K LOC | ~200K LOC | ~100K LOC |
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
- [x] Offline messaging via DHT store-and-forward
- [x] Group chat with Sender Keys (up to 100 members)
- [ ] File transfer
- [ ] Encrypted database (SQLCipher)
- [ ] Mobile clients

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
