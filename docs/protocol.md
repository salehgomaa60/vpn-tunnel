# VPN Tunnel Protocol Specification

## 1. Packet Types & Identifiers

All datagrams transmitted over the UDP transport begin with a 1-byte `packet_type` field:

| Type Code | Name | Description |
| :--- | :--- | :--- |
| `0x01` | `HANDSHAKE_INITIATION` | Sent by initiator to establish a new session |
| `0x02` | `HANDSHAKE_RESPONSE` | Sent by responder to complete key exchange |
| `0x03` | `TRANSPORT_DATA` | Encapsulated, authenticated VPN packet payload |
| `0x04` | `KEEPALIVE` | Zero-payload authenticated ping |

---

## 2. Transport Data Packet Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (0x03)  |                   Reserved                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Receiver Index                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Counter / Nonce (64-bit)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Encrypted Payload (Variable)                |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Poly1305 Authentication Tag (16B)              |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Parsing Invariants
1. `length >= 32` bytes (1 byte type + 3 reserved + 4 byte receiver index + 8 byte counter + 16 byte tag).
2. `Type == 0x03`.
3. `Receiver Index` maps to a known, established session.
4. `Counter` must not be duplicated or fall outside the replay protection sliding window.
5. Authenticated encryption tag must verify BEFORE any payload plaintext is processed.
