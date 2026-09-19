# Security Findings & Vulnerability Log

## Overview
This document tracks all security findings, fuzzing campaigns, memory safety verification,
and architectural threat modeling for the layer-3 VPN tunnel daemon.

> **Scope:** This document details the security posture, verification results, and empirical attack findings for the implementation.

---

## Attack-Surface Summary

| Priority | Component | Attacker Input | Mitigations |
|:---|:---|:---|:---|
| 🔴 CRITICAL | Handshake parser | Raw UDP before auth | Fixed-size frames, AEAD auth |
| 🔴 CRITICAL | AEAD decrypt | Ciphertext + tag | Authenticate-before-decrypt |
| 🟠 HIGH | Replay filter | 64-bit counter | 2048-entry sliding window bitmap |
| 🟠 HIGH | Data packet parser | Wire bytes | Strict length bounds, no heap alloc |
| 🟡 MEDIUM | Cryptographic routing | Decrypted src_ip | AllowedIPs CIDR verification |
| 🟡 MEDIUM | TUN write | Kernel packets | MTU bounds + EMSGSIZE guard |
| 🟢 LOW | Memory/keys | Process memory | sodium_memzero on teardown |

---

## Design Decisions with Security Rationale

### 1. Authenticate Before Decrypt
All incoming AEAD data is **always** authenticated before the plaintext buffer
is exposed to any downstream logic.  `vpn_crypto_aead_decrypt` returns
`-EBADMSG` and leaves the output buffer unmodified on failure.

**Attack prevented:** Padding oracle attacks, chosen-ciphertext attacks (CCA2).

### 2. Strict Packet Size Enforcement
Every parser (`packet_parse_handshake_init`, `packet_parse_handshake_resp`,
`packet_parse_data`) validates exact size constraints before touching any field.
Truncated or oversized frames are silently dropped.

**Attack prevented:** Buffer over-read, length-extension attacks.

### 3. Anti-Replay Before AEAD
`replay_check()` is called **before** `vpn_crypto_aead_decrypt()`.  Only after
decryption succeeds is `replay_update()` called.

**Rationale:** Prevents an attacker from exhausting the replay window by
injecting garbage packets whose counters happen to be in range.

### 4. Source IP Validation After Decryption
After successful decryption, the inner IP packet's source address is checked
against the peer's `AllowedIPs` CIDR list.

**Attack prevented:** IP spoofing / cross-peer traffic injection.

### 5. Constant-Time Comparisons
All security-sensitive comparisons use `sodium_memcmp` (constant-time) rather
than `memcmp`.

**Attack prevented:** Timing side-channel attacks on MAC verification.

### 6. Secure Memory Zeroization
All session keys, ephemeral private keys, and shared secrets are wiped with
`sodium_memzero` immediately after use.

**Attack prevented:** Cold-boot attacks, process memory dump key recovery.

---

## Fuzzing Harnesses

Four LibFuzzer harnesses are provided in `fuzz/`:

| Harness | Target | Sanitizers |
|:---|:---|:---|
| `fuzz_packet_parser` | All packet parsers | ASan + UBSan |
| `fuzz_aead` | `vpn_crypto_aead_decrypt` | ASan + UBSan |
| `fuzz_handshake` | Handshake consume functions | ASan + UBSan |
| `fuzz_replay` | Replay filter with invariant check | ASan + UBSan |

Build and run (Linux + clang):
```bash
make fuzz
mkdir -p fuzz/corpus && ./fuzz/gen_corpus fuzz/corpus/

# Run harnesses (example: 10-minute campaign each)
./fuzz/fuzz_packet_parser -max_len=2048 -max_total_time=600 fuzz/corpus/
./fuzz/fuzz_aead          -max_len=2000 -max_total_time=600 fuzz/corpus/
./fuzz/fuzz_handshake     -max_len=512  -max_total_time=600 fuzz/corpus/
./fuzz/fuzz_replay        -max_len=8192 -max_total_time=600
```

---

## Findings Log

*No security findings identified yet.*
*Update this section with any crashes, memory errors, or logic bugs found
during fuzzing or code review.*

---

## Known Scope & Future Protocol Extensions

- **No WireGuard protocol wire-compatibility** — this project uses a WireGuard-
  inspired Noise IK structure with custom binary framing, not intended to peer with official WireGuard kernels.
- **No DoS / cookie challenge** — the handshake processor performs BLAKE2b MAC1 verification, but does not implement the optional MAC2 cookie mechanism for high-volume DDoS mitigation.
- **Single-session transition model** — rekeying is supported via dual-session staging, but active rekey timers are driven by packet counters rather than automated wall-clock intervals.
- **Single-threaded event loop** — the `main.c` daemon utilizes a non-blocking `poll()` event loop optimized for clarity, determinism, and single-core efficiency.
- **No pre-shared key (PSK) layer** — the optional post-quantum / pre-shared key mixing step from Noise IKpsk2 is omitted.
