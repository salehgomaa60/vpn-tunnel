# Security Findings & Vulnerability Log

## Overview
This document tracks all security findings, fuzzing crashes, memory safety bugs,
and architectural vulnerabilities discovered during development and testing of
the educational VPN tunnel.

> **Note:** This is an educational project demonstrating security engineering
> principles.  It is NOT a production-grade VPN.

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

## Known Limitations (Educational Scope)

- **No WireGuard protocol compatibility** — this project uses a WireGuard-
  *inspired* structure but is NOT wire-compatible with WireGuard peers.
- **No DoS / rate-limiting** — the handshake processor does not throttle or
  cookie-challenge unauthenticated initiations.
- **No PFS-after-rekey beyond session boundary** — the rekeying path is
  stubbed; only a single session transition is preserved.
- **Single-threaded event loop** — the `main.c` daemon is single-threaded
  and not suitable for high-throughput or multi-peer deployment.
- **No pre-shared key (PSK) layer** — the optional WireGuard PSK mixing step
  is not implemented.
