# Educational Linux VPN Tunnel — Source Code Study Guide

Welcome! This codebase implements a clean, readable, WireGuard-inspired VPN tunnel daemon in C using `libsodium` (X25519, ChaCha20-Poly1305, BLAKE2b). Every source file is heavily commented to explain data structures, memory layouts, byte transformations, and security invariants.

---

## 🗺️ Architectural Roadmap

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

## 📂 File-by-File Line-by-Line Guide

| Module / File | Description & Key Educational Highlights |
| :--- | :--- |
| [`src/main.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/main.c) | **Event Loop Orchestrator.** `poll()` multiplexing over UDP socket & TUN device, full packet handling logic. |
| [`src/crypto.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/crypto.c) | **Libsodium Cryptography Wrapper.** ChaCha20-Poly1305 AEAD, X25519 DH, BLAKE2b hashing, 96-bit nonce formatting, `sodium_memzero`. |
| [`src/kdf.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/kdf.c) | **Key Derivation Functions.** HKDF-style `KDF1` and `KDF2` built over BLAKE2b for noise handshake key updates. |
| [`src/handshake.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/handshake.c) | **1-RTT Noise IK Handshake.** Handshake initiation/response creation and parsing, DH1..DH4 computation, chaining keys. |
| [`src/packet.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/packet.c) | **Wire Format & Zero-Copy Parsers.** Memory layouts, Little-Endian endianness conversion (`le32`, `le64`), buffer bounds. |
| [`src/peer.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/peer.c) | **Peer & Session Table.** Monotonic session index allocation, session key rotation (`current` vs `previous`), NAT roaming updates. |
| [`src/routing.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/routing.c) | **Cryptographic Routing.** Subnet mask arithmetic (`0xFFFFFFFF << (32 - prefix)`), CIDR string parsing, source IP authorization. |
| [`src/replay.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/replay.c) | **Anti-Replay Sliding Window.** 2048-bit bitmap array, 2-phase check-then-update invariant to prevent window corruption. |
| [`src/transport.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/transport.c) | **UDP Transport Socket.** Non-blocking sockets (`O_NONBLOCK`, `FD_CLOEXEC`), IPv4/IPv6 address parsing (`inet_pton`, `inet_ntop`). |
| [`src/tun.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/tun.c) | **Linux TUN Character Device.** `/dev/net/tun` allocation, `ioctl(TUNSETIFF)` flags (`IFF_TUN | IFF_NO_PI`), MTU configuration. |

---

## 🛠️ Building & Running

### Build standard binary & run unit tests:
```bash
make clean && make test
```

### Build executable daemon:
```bash
make vpn-tunnel
```

---

## 🔍 Key Security Invariants to Study

1. **Poly1305 AEAD Authentication Before Memory Modification**
   - In [`src/crypto.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/crypto.c), `crypto_aead_chacha20poly1305_ietf_decrypt()` verifies the 16-byte Poly1305 authentication tag *before* writing decrypted output.

2. **Two-Phase Anti-Replay Invariant**
   - In [`src/main.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/main.c), `replay_check()` is executed *before* AEAD decryption to drop replayed packets cheaply without wasting CPU.
   - `replay_update()` is executed *only after* AEAD decryption succeeds so unauthenticated attackers cannot force the window forward.

3. **Inbound Cryptographic Routing Check**
   - In [`src/main.c`](file:///c:/Users/HP/Desktop/personal%20projects/vpn-tunnel/src/main.c), after decrypting an inbound packet, the daemon extracts the inner IPv4 source address and checks `peer_allows_source_ip()` to ensure the peer is authorized to use that IP address.

4. **Zero-Memory Key Cleanup**
   - All secret keys and intermediate Diffie-Hellman buffers are erased using `vpn_crypto_memzero()` to prevent key material from lingering in RAM.
