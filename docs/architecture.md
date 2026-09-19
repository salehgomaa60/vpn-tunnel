# VPN Tunnel Architecture

## 1. High-Level Core Data Flow

```
+-------------------------------------------------------------+
|                      User Application                       |
+-------------------------------------------------------------+
                              |
                              v (raw IP datagram)
+-------------------------------------------------------------+
|                      Linux TUN Interface                    |
|                        (/dev/net/tun)                       |
+-------------------------------------------------------------+
                              |
                              v (read plaintext IP packet)
+-------------------------------------------------------------+
|                        VPN Daemon                           |
|  - Cryptographic Routing Table (AllowedIPs matching)       |
|  - Session / Peer State Lookup                              |
|  - Directional AEAD Encryption (ChaCha20-Poly1305)          |
|  - Monotonic 64-bit Nonce / Counter                         |
|  - Binary Wire Format Serialization                         |
+-------------------------------------------------------------+
                              |
                              v (encrypted VPN transport datagram)
+-------------------------------------------------------------+
|                        UDP Socket                           |
|                       (Port 51820)                          |
+-------------------------------------------------------------+
                              |
                              v (Internet / Hostile Network)
```

---

## 2. Inbound Reception Data Flow

```
+-------------------------------------------------------------+
|                        UDP Socket                           |
+-------------------------------------------------------------+
                              |
                              v (untrusted datagram)
+-------------------------------------------------------------+
|                   Hardened Zero-Trust Parser                |
|  - Bounds check minimum / maximum length                    |
|  - Strict packet type / version validation                  |
|  - Receiver index / peer resolution                         |
|  - Sliding-window replay filter check                       |
+-------------------------------------------------------------+
                              |
                              v (authenticated payload)
+-------------------------------------------------------------+
|                  Authenticated Decryption                   |
|  - Poly1305 tag verification BEFORE plaintext acceptance    |
|  - ChaCha20 decryption                                      |
+-------------------------------------------------------------+
                              |
                              v (plaintext IP packet)
+-------------------------------------------------------------+
|                   Cryptographic Routing Check               |
|  - Validate inner packet source IP against peer AllowedIPs  |
+-------------------------------------------------------------+
                              |
                              v (write to virtual interface)
+-------------------------------------------------------------+
|                      Linux TUN Interface                    |
+-------------------------------------------------------------+
```
