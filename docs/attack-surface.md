# Attack Surface & Component Security Analysis

| Component | Attacker-Controlled Input | Trust Boundary | Primary Mitigations | Failure Modes & Handling |
| :--- | :--- | :--- | :--- | :--- |
| **UDP Socket / Parser** | Raw network UDP datagrams | External / Hostile | Strict minimum & maximum size validation, binary framing checks, zero-trust parser | Drop packet silently, no memory allocation on untrusted length |
| **Handshake Processor** | Handshake initiation / response packets | External / Hostile | Fixed-size message frames, authenticated Diffie-Hellman, transcript hashing | Drop invalid / mismatched ephemeral messages |
| **AEAD Decryption** | Ciphertext payload & 16-byte Poly1305 tag | External / Hostile | Authenticate tag before exposing or acting on plaintext | Reject and drop frame on decryption failure |
| **Replay Protection** | 64-bit packet sequence numbers | External / Hostile | Sliding window bitmap filter, monotonic counter enforcement | Discard replayed or excessively stale packet counters |
| **Cryptographic Routing** | Decrypted inner IP header (`src_ip`) | Internal / Decrypted | AllowedIPs CIDR verification per peer | Drop packet if source IP is not in peer's AllowedIPs list |
| **TUN Interface** | Kernel virtual network packets | Local host / Kernel | Checked buffer reads/writes, MTU bounds checking | Log warning and discard oversized packet |
| **Memory / Secrets** | Ephemeral & session keys | Process memory | `sodium_memzero` on teardown, no secret logging | Secure zeroization prevents memory dumps leaking keys |
