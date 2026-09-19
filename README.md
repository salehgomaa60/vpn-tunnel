# Educational Linux VPN Tunnel in C

A clean, readable, WireGuard-inspired Layer-3 VPN tunnel daemon written in C (C99) using `libsodium`.

Designed specifically for **line-by-line educational study**, protocol analysis, and hands-on security research. Every component features extensive inline documentation explaining byte layouts, state transitions, cryptographic invariants, and system calls.

---

## 🚀 Key Features & Subsystems

- **WireGuard-Inspired Cryptography:** Uses established primitives via `libsodium`:
  - **Key Exchange:** 1-RTT Noise IK handshake with Curve25519 (`crypto_scalarmult_curve25519`).
  - **Authenticated Encryption:** ChaCha20-Poly1305 AEAD (`crypto_aead_chacha20poly1305_ietf`).
  - **Key Derivation:** HKDF-style `KDF1` and `KDF2` built over BLAKE2b (`crypto_generichash`).
  - **Directional Session Keys:** Independent 256-bit `send_key` and `recv_key` derived after handshake completion.
- **Linux TUN Interface (`src/tun.c`):** Raw Layer-3 IPv4 packet virtual device using `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`.
- **Non-blocking UDP Transport (`src/transport.c`):** Asynchronous socket I/O supporting IPv4/IPv6 endpoints and automatic NAT traversal (Endpoint Roaming).
- **Cryptographic Routing (`src/routing.c`, `src/peer.c`):** AllowedIPs CIDR subnet mapping. Verifies inner IP ownership both outbound and inbound to prevent IP spoofing.
- **Anti-Replay Protection (`src/replay.c`):** 2048-bit sliding window bitmap filter enforcing strict two-phase verification (check before decrypt, update only after AEAD authentication).
- **Zero-Copy Packet Parsing (`src/packet.c`):** Fixed wire layout serialization/deserialization with explicit Little-Endian endianness conversion (`le32_read`, `le64_write`).
- **Comprehensive Unit & Fuzz Tests (`tests/`, `fuzz/`):** Test suites covering all components, state machines, and LibFuzzer harnesses for parser security.

---

## 🗺️ High-Level Architecture

```text
                        +--------------------------------+
                        |        Linux OS Kernel         |
                        | (Apps send IP packets to vpn0) |
                        +---------------+----------------+
                                        |
                             read() / write()
                                        v
                        +--------------------------------+
                        |   TUN Virtual Interface        |  [src/tun.c]
                        +---------------+----------------+
                                        |
                             Cleartext IP Packets
                                        v
+--------------------------------------------------------------------------------+
|                             VPN DAEMON EVENT LOOP                              |  [src/main.c]
|                                                                                |
|  Outbound Pipeline (TUN -> UDP):                                                |
|    1. Read cleartext IP packet from TUN device                                 |
|    2. Parse destination IPv4 address from packet header (offset 16)            |
|    3. Perform Cryptographic Routing lookup in Peer Table (AllowedIPs CIDRs)     |  [src/peer.c, src/routing.c]
|    4. Encrypt IP payload with AEAD (ChaCha20-Poly1305 + 64-bit Nonce Counter)   |  [src/crypto.c]
|    5. Serialize DATA wire packet (16B header + Ciphertext + 16B Poly1305 Tag)   |  [src/packet.c]
|    6. Send encrypted UDP datagram to peer endpoint                             |  [src/transport.c]
|                                                                                |
|  Inbound Pipeline (UDP -> TUN):                                                 |
|    1. Receive UDP datagram on non-blocking socket                              |  [src/transport.c]
|    2. Peek packet type byte (0x01 Init, 0x02 Resp, 0x03 Data)                  |  [src/packet.c]
|    3. Parse wire header & lookup peer/session by 32-bit `receiver_index`       |  [src/peer.c]
|    4. Anti-Replay PRE-CHECK using 2048-bit sliding window                      |  [src/replay.c]
|    5. Decrypt & Authenticate AEAD payload using Poly1305 auth tag              |  [src/crypto.c]
|    6. On Success: UPDATE anti-replay filter bitmap & update endpoint roaming   |  [src/replay.c, src/peer.c]
|    7. Verify source IP matches peer's AllowedIPs CIDR subnet                   |  [src/routing.c]
|    8. Write decrypted cleartext IP packet into TUN device for OS delivery      |  [src/tun.c]
+--------------------------------------------------------------------------------+
                                        |
                            Encrypted UDP Datagrams
                                        v
                        +--------------------------------+
                        |     UDP Network Socket         |  [src/transport.c]
                        +--------------------------------+
```

---

## 📖 Study Guide & Documentation

For a detailed file-by-file roadmap and line-by-line code study guide, see:
- [**`STUDY_GUIDE.md`**](STUDY_GUIDE.md) — Comprehensive guide to every source file, byte transformation, and cryptographic invariant.
- [**`docs/architecture.md`**](docs/architecture.md) — System architecture breakdown.
- [**`docs/protocol.md`**](docs/protocol.md) — Handshake & wire protocol specifications.
- [**`docs/threat-model.md`**](docs/threat-model.md) — Security threat model and boundary definitions.

---

## 🛠️ Building and Running

### Prerequisites
- **OS:** Linux (or WSL2 on Windows)
- **Compiler:** `gcc` or `clang` (C99 standard)
- **Libraries:** `libsodium` development headers & library (`libpthread`)

### Compilation

Build the complete project and unit test executables:
```bash
make clean && make test
```

Build the daemon executable (`vpn-tunnel`):
```bash
make vpn-tunnel
```

Run in debug logging mode:
```bash
sudo ./vpn-tunnel --debug
```

---

## 📁 Repository Directory Structure

```text
├── Makefile                # Build configurations (GCC/Clang, ASan, Fuzzing)
├── README.md               # Main repository documentation
├── STUDY_GUIDE.md          # Line-by-line source code learning guide
├── docs/                   # Protocol specifications & threat model docs
├── exercises/              # Hands-on protocol & cryptographic exercises
├── fuzz/                   # LibFuzzer security harnesses for packet parser & AEAD
├── src/                    # Primary C source code implementation
│   ├── main.c              # POSIX poll() event loop orchestrator
│   ├── crypto.c / .h       # Libsodium wrapper & AEAD primitives
│   ├── kdf.c / .h          # HKDF-style key derivation logic
│   ├── handshake.c / .h    # 1-RTT Noise IK handshake state machine
│   ├── packet.c / .h       # Wire format serialization & parsing
│   ├── peer.c / .h         # Peer table, sessions, and endpoint roaming
│   ├── routing.c / .h      # Cryptographic Routing & CIDR math
│   ├── replay.c / .h       # 2048-bit anti-replay sliding window
│   ├── transport.c / .h    # Non-blocking UDP socket I/O
│   └── tun.c / .h          # Linux TUN device driver interface
└── tests/                  # Unit test framework & test suites
```

---

## 📜 License

This project is released for educational and research purposes.
