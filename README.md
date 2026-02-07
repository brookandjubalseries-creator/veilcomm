<p align="center">
  <img src="https://img.shields.io/badge/rust-2021-orange?style=flat-square&logo=rust" alt="Rust 2021">
  <img src="https://img.shields.io/badge/crypto-post--quantum-blueviolet?style=flat-square" alt="Post-Quantum">
  <img src="https://img.shields.io/badge/transport-QUIC-00e5ff?style=flat-square" alt="QUIC">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/tests-117%20passing-brightgreen?style=flat-square" alt="Tests">
</p>

# VeilComm

**Post-quantum encrypted P2P messaging with features no other messenger has.**

VeilComm is a from-scratch Rust implementation of a secure P2P chat system that combines classical elliptic-curve cryptography with Kyber-1024 lattice-based post-quantum protection. Every message is end-to-end encrypted with forward secrecy via the Double Ratchet protocol, keys are exchanged through a hybrid PQXDH handshake, and peers communicate directly over QUIC with Kademlia DHT discovery.

---

## What Makes VeilComm Different

These features don't exist together in any messenger -- Signal, Session, Briar, Tox, Matrix, or otherwise.

### Duress Password (Decoy Vault)

Unlock with your real password and see your real contacts and messages. Unlock with a duress password under coercion and a completely separate decoy vault opens -- different contacts, different messages, different database. There's no way to prove the real vault exists. The keystore uses trial decryption with no password hash stored, so even forensic analysis can't distinguish which vault is real.

```
Real password    ──> Vault A (real contacts, real messages)
Duress password  ──> Vault B (decoy contacts, decoy messages)
                     No hash stored. No way to prove Vault A exists.
```

### Steganographic Transport

Hide encrypted message payloads inside ordinary BMP images using LSB steganography. The output is a valid image file that looks like random noise. Toggle stego mode in the chat header and your encrypted payloads are embedded in carrier images at 3 bits per pixel across R/G/B channels.

### Dead Man's Switch

Schedule messages to be automatically delivered to chosen contacts if you fail to check in within a set interval. Configure multiple independent switches with different recipients, messages, and timers. Pause, resume, or delete at any time. If the deadline passes without a check-in, the messages fire.

### LAN Mesh Networking

Communicate with nearby peers over the local network without any internet connection. UDP multicast discovery on `239.255.77.67:5367` automatically finds other VeilComm nodes on your LAN segment. No bootstrap nodes, no DHT, no internet required.

| Feature | Signal | Session | Briar | Tox | Matrix | **VeilComm** |
|---------|--------|---------|-------|-----|--------|-------------|
| Duress/Decoy Vault | No | No | No | No | No | **Yes** |
| Steganographic Transport | No | No | No | No | No | **Yes** |
| Dead Man's Switch | No | No | No | No | No | **Yes** |
| LAN Mesh (No Internet) | No | No | WiFi/BT | LAN | No | **Yes** |
| Post-Quantum Crypto | Yes | No | No | No | Experimental | **Yes** |
| Serverless P2P | No | Partial | Yes | Yes | No | **Yes** |
| Offline Messaging | Yes | Yes | Partial | No | Yes | **Yes** |
| Group Chat | Yes | Yes | Yes | Yes | Yes | **Yes** |

---

## All Features

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
| **Duress Protection** | Two-vault keystore with trial decryption, no password hash |
| **Steganography** | BMP LSB encoding (3 bits/pixel), valid image output |
| **Dead Man's Switch** | Timed auto-delivery with configurable intervals |
| **LAN Mesh** | UDP multicast peer discovery, no internet required |
| **Peer Discovery** | Kademlia DHT with iterative lookup |
| **NAT Traversal** | STUN for public address discovery |
| **Key Storage** | Argon2id-encrypted keystore (64 MiB, 3 iterations) |
| **Identity** | Ed25519 signatures + X25519 DH + Kyber-1024 KEM |
| **Interface** | Web GUI (glassmorphism) + CLI |

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
# Opens http://127.0.0.1:3000
```

Features include:
- **Delivery status indicators**: clock (pending), cloud (queued in DHT), single check (sent), double check (delivered/read)
- **Group chat**: create groups from your contacts, per-sender colored message labels, group info panel
- **Offline message polling**: automatically checks for queued messages every 30 seconds
- **Duress vault setup**: configure a decoy vault from Settings > Duress Protection
- **Dead Man's Switch management**: create/pause/delete switches, one-click check-in from Settings
- **LAN Mesh panel**: start/stop mesh discovery, see discovered peers in the Network tab
- **Stego mode toggle**: click STEGO in the chat header to wrap payloads in images

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
│   │   ├── protocol/
│   │   │   ├── session.rs   # Encrypted session management
│   │   │   ├── message.rs   # Message types & serialization
│   │   │   └── group.rs     # Group protocol types & actions
│   │   └── steganography.rs # BMP LSB steganographic encoding
│   │
│   ├── veilcomm-network/    # P2P networking
│   │   ├── transport/
│   │   │   ├── quic.rs      # QUIC transport (quinn)
│   │   │   └── tor.rs       # Tor transport (TCP+TLS via SOCKS5)
│   │   ├── dht/             # Kademlia DHT (20-bucket, k=20)
│   │   ├── service.rs       # Network service + offline messaging
│   │   ├── protocol.rs      # Wire protocol (bincode-serialized)
│   │   ├── peer.rs          # Connection manager + peer lifecycle
│   │   ├── mesh.rs          # LAN mesh discovery (UDP multicast)
│   │   └── nat.rs           # STUN NAT traversal
│   │
│   ├── veilcomm-storage/    # Persistent storage
│   │   ├── keystore.rs      # Argon2id keystore (V1 standard + V2 duress two-vault)
│   │   └── database.rs      # SQLite (contacts, messages, sessions, groups, DMS)
│   │
│   ├── veilcomm-app/        # Application logic
│   │   └── client.rs        # VeilCommClient API (chat, duress, DMS, mesh, stego)
│   │
│   ├── veilcomm-cli/        # Terminal interface
│   └── veilcomm-gui/        # Web GUI (axum + embedded HTML)
│       ├── src/main.rs       # REST API server (40+ endpoints)
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

### Duress Keystore (V2)

The V2 keystore format provides plausible deniability under coercion:

- Two encrypted slots in a single file -- one for the real vault, one for the decoy
- **No password hash stored** -- the keystore uses trial decryption against both slots
- Each vault has its own identity, pre-keys, and a unique `db_token` that maps to a separate SQLite database
- Magic bytes `VK02` distinguish V2 from V1; `load_keystore()` auto-detects the format
- `db_token` is derived via BLAKE2s and mapped to a filename, so each vault's data is physically isolated
- An adversary with access to the keystore file cannot determine how many vaults exist or which password opens which

### Steganographic Encoding

Messages can be hidden in valid BMP image files using LSB steganography:

- 3 bits per pixel (1 LSB per R/G/B channel in 24-bit BMP)
- 4-byte little-endian length prefix followed by the payload
- Carrier images are auto-generated with random pixel data
- The output is a valid `.bmp` file that can be opened in any image viewer
- Capacity scales with image dimensions: a 256x256 image holds ~24 KB

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
- V2 duress keystore: two encrypted vaults, trial decryption, no password hash
- All cryptographic keys zeroized on drop (Ed25519, X25519, Kyber-1024, Sender Keys)
- SQLite database for contacts, messages, sessions, groups, sender keys, and dead man's switches
- Separate database file per vault when duress protection is enabled

## Testing

```bash
# Run all 117 tests
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
| `veilcomm-core` | 62 | AEAD, KDF, keys, X3DH, Double Ratchet, PQ, sessions, Sender Keys, group protocol, steganography |
| `veilcomm-network` | 33 | QUIC transport, DHT, offline messages, connection manager, protocol, STUN, NAT, Tor, mesh discovery |
| `veilcomm-storage` | 22 | Keystore V1/V2, duress vault, password change, database CRUD, sessions, groups, sender keys, delivery status, dead man's switches |

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

**Unique Feature Set**

No other messenger combines duress protection, steganographic transport, dead man's switches, and LAN mesh networking. These features are designed for scenarios where existing tools fall short -- adversarial environments, network-denied operations, and plausible deniability under coercion.

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

~15,000 lines of Rust. The entire cryptographic stack can be reviewed in an afternoon. Signal's codebase spans hundreds of thousands of lines across Java, Swift, and TypeScript. Smaller attack surface, easier to verify.

### Where VeilComm falls short (honest assessment)

**No professional security audit.** This is the biggest gap. Signal's protocol has been formally verified by academic researchers and audited by firms like NCC Group. VeilComm has not. "The code compiles and tests pass" is not the same as "this is secure against a nation-state adversary."

**Metadata protection is optional.** By default, direct QUIC connections expose both peers' IP addresses. Tor onion routing can be enabled to hide IPs, but it is opt-in and requires running a Tor daemon. Signal has sealed sender and private contact discovery built-in. Session has mandatory onion routing. Briar routes through Tor by default.

**No mobile apps.** Desktop only, requires building from source.

**Unencrypted message database.** The identity keystore is encrypted with Argon2id + ChaCha20-Poly1305, but the SQLite database storing messages and contacts is not encrypted at rest. Signal uses SQLCipher. This is a known gap (partially mitigated by duress vault separation).

### Summary

| Feature | VeilComm | Signal | Tox | Session | Briar |
|---------|----------|--------|-----|---------|-------|
| Post-Quantum | **Hybrid PQ** | **Hybrid PQ** | None | None | None |
| Forward Secrecy | **Double Ratchet** | **Double Ratchet** | None | Partial | **Yes** |
| Serverless P2P | **Yes** | No | **Yes** | Partial | **Yes** |
| Metadata Protection | Tor optional | Good | Poor | **Strong** | **Strong** |
| Offline Messaging | **DHT relay** | **Yes** | None | **Yes** | Partial |
| Group Chat | **Sender Keys** | **Yes** | **Yes** | **Yes** | **Yes** |
| Duress Protection | **Yes** | No | No | No | No |
| Steganography | **Yes** | No | No | No | No |
| Dead Man's Switch | **Yes** | No | No | No | No |
| LAN Mesh | **Yes** | No | LAN | No | WiFi/BT |
| Security Audits | None | **Extensive** | Some | Some | **Yes** |
| Mobile Apps | None | **Yes** | Partial | **Yes** | **Yes** |
| Codebase Size | **~15K LOC** | ~500K+ LOC | ~100K LOC | ~200K LOC | ~100K LOC |
| Language | **Rust** | Java/Swift/TS | C | Kotlin/Swift | Java |

**VeilComm is a strong cryptographic foundation with capabilities no production messenger offers.** It demonstrates that post-quantum P2P messaging with advanced operational security features can be built from scratch in Rust with a small, auditable codebase. It is not yet suitable for high-stakes communication -- use Signal for that until VeilComm matures.

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
- [x] Duress password with decoy vault (V2 keystore)
- [x] Steganographic transport (BMP LSB encoding)
- [x] Dead man's switch with configurable timers
- [x] LAN mesh networking (UDP multicast, no internet)
- [ ] File transfer
- [ ] Encrypted database (SQLCipher)
- [ ] Mobile clients

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
