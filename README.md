# Building a WireGuard-Style Layer-3 VPN Tunnel from Scratch in C

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![C Standard](https://img.shields.io/badge/C-C99-blue.svg)]()
[![Crypto](https://img.shields.io/badge/crypto-libsodium%20%28Noise%20IK%29-orange.svg)]()
[![Security](https://img.shields.io/badge/security-LibFuzzer%20%26%20ASan-purple.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A high-performance, secure Layer-3 VPN tunnel daemon implemented from first principles in C99. Built around the **Noise IK** 1-RTT handshake pattern, **ChaCha20-Poly1305** authenticated encryption (AEAD), and Linux **TUN** virtual network interfaces.

This project was built to explore the deep systems-level realities of secure network tunneling: memory layout engineering, non-blocking asynchronous event loops, zero-copy wire parsers, constant-time cryptographic verification, and defense-in-depth against packet injection and replay attacks.

---

## 🏗️ Architectural Overview

The daemon runs in userspace, bridging the Linux kernel networking stack with the untrusted public Internet via non-blocking I/O (`poll`):

```
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
                             Cleartext IPv4 Packets
                                        v
+--------------------------------------------------------------------------------+
|                             VPN DAEMON EVENT LOOP                              |  [src/main.c]
|                                                                                |
|  Outbound Pipeline (TUN -> UDP):                                               |
|    1. Read cleartext IP packet from TUN descriptor                             |
|    2. Extract destination IPv4 address from IP header                          |
|    3. Perform Cryptographic Routing lookup against peer AllowedIPs CIDRs       |  [src/routing.c]
|    4. Encrypt payload with ChaCha20-Poly1305 AEAD (64-bit monotonic counter)   |  [src/crypto.c]
|    5. Construct DATA frame (16B header + Ciphertext + 16B Poly1305 Tag)        |  [src/packet.c]
|    6. Transmit encrypted UDP datagram to peer endpoint                         |  [src/transport.c]
|                                                                                |
|  Inbound Pipeline (UDP -> TUN):                                                |
|    1. Receive datagram from non-blocking UDP socket                            |  [src/transport.c]
|    2. Peek packet type byte (0x01 Init, 0x02 Resp, 0x03 Data)                  |  [src/packet.c]
|    3. Lookup session & cryptographic context by 32-bit `receiver_index`        |  [src/peer.c]
|    4. Anti-Replay PRE-CHECK against 2048-bit sliding window bitmap             |  [src/replay.c]
|    5. Decrypt & Authenticate AEAD payload using Poly1305 auth tag              |  [src/crypto.c]
|    6. Commit: UPDATE anti-replay filter bitmap & roam peer endpoint            |  [src/replay.c]
|    7. Cryptographic Routing: verify decrypted source IP matches peer subnet    |  [src/routing.c]
|    8. Write cleartext IP packet to TUN device for OS delivery                  |  [src/tun.c]
+--------------------------------------------------------------------------------+
                                        |
                             Encrypted UDP Datagrams
                                        v
                        +--------------------------------+
                        |     UDP Network Socket         |  [src/transport.c]
                        +--------------------------------+
```

---

## ⚡ Key Engineering Highlights

### 1. Cryptographic Protocol & Key Exchange
- **1-RTT Noise IK Handshake (`src/handshake.c`):** Mutual authentication and key exchange completed in a single round trip. The initiator knows the responder's static public key beforehand; initiator static identity is transmitted encrypted over the wire (identity hiding).
- **Curve25519 (X25519) ECDH:** Constant-time scalar multiplication (`crypto_scalarmult_curve25519`) immune to cache-timing attacks.
- **Directional Session Keys:** Derives independent 256-bit `send_key` and `recv_key` via BLAKE2b KDF (`src/kdf.c`) to eliminate nonce coordination bottlenecks between peers.
- **Forward Secrecy:** Ephemeral keys are securely zeroized (`sodium_memzero`) immediately following session key derivation.

### 2. High-Assurance Packet Pipeline
- **Zero Heap Allocations on Hot Path:** The main packet read/write loop executes entirely on pre-allocated stack/static buffers. Zero `malloc` calls during active data transit.
- **Strict Little-Endian Wire Layout:** Fixed binary formats with zero-copy struct parsing and explicit byte-order conversions (`le32_read`, `le64_write`).
- **Authenticate-Before-Decrypt:** Poly1305 128-bit MAC tag is verified *before* exposing any decrypted buffer to downstream processing, eliminating padding oracle and malleability vulnerabilities.

### 3. RFC 6479 Anti-Replay Protection
- Implements a **2048-bit sliding window filter** using a 32-element `uint64_t` bitmap array.
- **Two-Phase Commit Invariant:** `replay_check()` evaluates counters in $O(1)$ time prior to AEAD decryption. If decryption fails, `replay_update()` is never invoked, preventing attackers from advancing or desynchronizing the window with forged frames.

### 4. Cryptographic Routing & Roaming
- **Cryptographic Routing (`src/routing.c`):** Binds each peer's cryptographic public key to authorized CIDR IP prefixes (`AllowedIPs`). Inbound cleartext IP packets are checked against the peer's subnet mask; unauthorized inner IPs are instantly dropped to prevent cross-peer spoofing.
- **NAT Endpoint Roaming:** Incoming authenticated packets automatically update the peer's dynamic remote endpoint (IP/port), enabling seamless handoffs across Wi-Fi/mobile networks without renegotiation.

---

## 🛡️ Security Verification & Offensive Testing

Security wasn't an afterthought—it was validated through continuous fuzzing and automated attack scripts:

### Automated Attack Suite (`attacks/`)
A dedicated suite of Python harnesses attacks the daemon over the wire to verify defensive invariants:

| Test Harness | Attack Vector Tested | Defensive Invariant Verified |
| :--- | :--- | :--- |
| `attack1_random.py` | Pseudorandom byte flooding | $O(1)$ fast rejection at `packet_parse_type()` |
| `attack2_truncated.py` | Runt packets (< minimum wire length) | Strict size bounds check before field parsing |
| `attack3_replay.py` | Packet capture & retransmission | 2048-bit sliding window rejects duplicate counter |
| `attack4_bitflip.py` | Ciphertext / Poly1305 bit tampering | AEAD verification failure (`-EBADMSG`); zeroized buffer |
| `attack5_wrong_index.py` | Session ID confusion & spoofing | Peer lookup rejection; drops invalid receiver indices |
| `attack6_corrupt_handshake.py` | Mutated initiation frames | BLAKE2b MAC1 failure drops packet before DH point mult |
| `attack7_oversized.py` | Jumbo MTU buffer overflow attempt | Truncation & drop at transport layer; no memory corruption |
| `attack8_counter_inject.py` | Future counter injection ($C + 10^5$) | Check-then-update invariant keeps replay window intact |

### Fuzzing & Memory Sanitizers (`fuzz/`)
Four dedicated LibFuzzer harnesses continuously test the parser and crypto boundaries under AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan):
- `fuzz_packet_parser`: Unconstrained fuzzing of all wire deserializers.
- `fuzz_aead`: Arbitrary ciphertext and nonce validation.
- `fuzz_handshake`: Handshake state machine mutation.
- `fuzz_replay`: Sliding-window state transition and boundary testing.

---

## 📁 Repository Structure

```text
.
├── Makefile                # Build system (GCC/Clang, sanitizers, fuzzer targets)
├── README.md               # Systems architecture and technical overview
├── attacks/                # Empirical wire attack test suite (Python 3)
│   ├── attack1_random.py
│   ├── ...
│   └── attack8_counter_inject.py
├── docs/                   # Engineering specifications & threat modeling
│   ├── architecture.md     # Detailed data flow and pipeline diagrams
│   ├── attack-surface.md   # Attack surface component analysis
│   ├── protocol.md         # Wire format layouts and parsing invariants
│   ├── security-findings.md# Empirical findings log & protocol scope
│   └── threat-model.md     # Assets, boundaries, and security assumptions
├── fuzz/                   # LibFuzzer security harnesses
│   ├── fuzz_aead.c
│   ├── fuzz_handshake.c
│   ├── fuzz_packet_parser.c
│   └── fuzz_replay.c
├── src/                    # Core C99 daemon implementation
│   ├── main.c              # Asynchronous poll() event loop orchestrator
│   ├── crypto.c / .h       # Libsodium primitives wrapper (ChaCha20-Poly1305, X25519)
│   ├── handshake.c / .h    # 1-RTT Noise IK handshake state machine
│   ├── kdf.c / .h          # BLAKE2b HKDF key derivation logic
│   ├── packet.c / .h       # Binary wire format serialization and zero-copy parsers
│   ├── peer.c / .h         # Peer routing table, session keys, and roaming
│   ├── replay.c / .h       # 2048-bit sliding window anti-replay filter
│   ├── routing.c / .h      # CIDR parsing and cryptographic routing checks
│   ├── transport.c / .h    # Non-blocking UDP socket I/O
│   └── tun.c / .h          # Linux TUN virtual network interface driver
└── tests/                  # Complete unit test suite
```

---

## 🛠️ Building & Running

### Prerequisites
- **OS:** Linux (Ubuntu 20.04+, Debian, Arch, or WSL2)
- **Compiler:** `gcc` or `clang` (C99 support)
- **Dependencies:** `libsodium-dev`, `pthread`

```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y build-essential libsodium-dev
```

### Build & Test Commands

```bash
# 1. Compile all unit test suites and verify correctness
make clean && make test

# 2. Build the production daemon binary
make vpn-tunnel

# 3. Build with AddressSanitizer & UndefinedBehaviorSanitizer
make asan

# 4. Run under Valgrind memory leak verification
valgrind --leak-check=full --show-leak-kinds=all ./tests/test_packet

# 5. Build LibFuzzer security harnesses (requires clang)
make fuzz
```

### Running the Daemon

```bash
# Launch daemon with debug logging enabled
sudo ./vpn-tunnel --debug
```

---

## 📚 Technical Documentation

For deep technical specifications, refer to the documentation suite in `docs/`:
- [**Architecture Specification**](docs/architecture.md) — Event loop mechanics, TUN read/write cycles, and thread model.
- [**Protocol Specification**](docs/protocol.md) — Detailed binary wire formats, byte offsets, and parser invariants.
- [**Attack Surface Analysis**](docs/attack-surface.md) — Trust boundaries, component-by-component vulnerability mitigations.
- [**Threat Model**](docs/threat-model.md) — Security assets, adversary capabilities, and out-of-scope conditions.
- [**Security Findings Log**](docs/security-findings.md) — Empirical verification results, audit findings, and future protocol roadmap.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
