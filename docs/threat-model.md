# Threat Model

## 1. Assets to Protect
1. **Confidentiality of Tunnel Plaintext**: User IP traffic traveling through the tunnel must never be readable by network eavesdroppers.
2. **Integrity & Authenticity of Tunnel Traffic**: An attacker on the network must not be able to forge, alter, or tamper with packets without immediate cryptographic detection and rejection.
3. **Session Keys & Long-Term Private Keys**: Static private keys and ephemeral session keys must remain strictly confidential in memory and wiped upon session destruction.
4. **Anti-Replay Security**: Old packets captured by an attacker must not be accepted again by the tunnel daemon.
5. **System Availability & Daemon Stability**: Hostile network datagrams must not crash the daemon, leak memory, or cause unbounded resource consumption.

---

## 2. Attacker Capabilities & Trust Boundaries
- **Untrusted Network**: The UDP network interface is completely hostile. An attacker can inject, capture, drop, reorder, delay, mutate, or duplicate arbitrary UDP datagrams.
- **Local Host Trust**: The local Linux kernel, root user, and memory of the daemon process are trusted.
- **Virtual TUN Interface**: The TUN interface receives plaintext IP packets from the local OS routing stack. It is trusted to deliver valid IP packets destined for the tunnel.

---

## 3. Security Assumptions & Out of Scope
- **Cryptographic Primitives**: libsodium implementation of Curve25519, ChaCha20-Poly1305, and BLAKE2b is assumed to be cryptographically sound and constant-time.
- **Side Channels**: Hardware physical side-channel attacks (e.g. power analysis, physical tampering) are out of scope.
- **Endpoint Compromise**: If the host machine running the VPN daemon is compromised at the root/kernel level, protection of keys is out of scope.
