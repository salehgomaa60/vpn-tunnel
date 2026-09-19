"""
Attack 6: Corrupt Handshake Packet (Noise IK Tampering)
=======================================================
Goal: Send a structurally valid 148-byte HANDSHAKE_INIT packet, but with
      completely random (garbage) crypto fields. The server:
        1. Accepts the structure (type=0x01, len=148 ✓)
        2. Verifies MAC1 — FAILS (our MAC1 is random, not computed correctly)
        3. Drops the packet before any session state is created

This simulates an attacker who knows the wire format but doesn't have the
server's static public key (needed to compute MAC1 correctly).

Noise IK Handshake wire layout (148 bytes):
  Offset  Size  Field
  ------  ----  -----
  0       1     Type = 0x01
  1       3     Reserved = 0x00 0x00 0x00
  4       4     SenderIndex (LE32) — attacker chosen
  8       32    Ephemeral public key E_i (unencrypted)
  40      48    encrypted_static: AEAD(S_i_pub, 16-byte tag)
  88      28    encrypted_timestamp: AEAD(12-byte timestamp, 16-byte tag)
  116     16    MAC1: BLAKE2b-16(key=H(S_r_pub), msg=bytes[0..115])
  132     16    MAC2: zeros in our implementation
  ---     ---
  Total: 148

The MAC1 must be computed with the server's real static public key.
Without it, MAC1 will be wrong and the handshake is rejected immediately.

Code path:
  packet_parse_handshake_init() → structural parse OK
  handshake_process_init()       → MAC1 check → FAIL → drop

Expected server log:
  [WARN] handshake_process_init: MAC1 verification failed — dropping handshake

How to run:
  python3 attack6_corrupt_handshake.py
"""

import socket
import struct
import os


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = ("127.0.0.1", 51820)

    sender_index = 0xAABBCCDD   # attacker's chosen session index

    pkt = bytearray(148)

    # Type byte and reserved
    pkt[0] = 0x01               # HANDSHAKE_INIT
    pkt[1] = 0x00               # reserved
    pkt[2] = 0x00               # reserved
    pkt[3] = 0x00               # reserved

    # Sender index (LE32 at offset 4)
    struct.pack_into("<I", pkt, 4, sender_index)

    # Unencrypted ephemeral public key (32 bytes at offset 8)
    # Real key should be a valid Curve25519 point, but we use random bytes
    pkt[8:40]   = os.urandom(32)

    # encrypted_static (48 bytes at offset 40)
    # Real: AEAD(S_i_pub[32], key=derived_from_handshake_chain, tag=16)
    # Fake: random garbage
    pkt[40:88]  = os.urandom(48)

    # encrypted_timestamp (28 bytes at offset 88)
    # Real: AEAD(12-byte-timestamp, key=derived, tag=16)
    # Fake: random garbage
    pkt[88:116] = os.urandom(28)

    # MAC1 (16 bytes at offset 116)
    # Real: BLAKE2b-16(key=Hash(S_r_pub), msg=pkt[0:116])
    # Fake: random (we don't have the server's public key)
    pkt[116:132] = os.urandom(16)

    # MAC2 (16 bytes at offset 132) — zeros in our implementation
    pkt[132:148] = bytes(16)

    print(f"[*] Corrupt Handshake Init Attack (Noise IK Tampering)")
    print(f"[*] Target: {target[0]}:{target[1]}")
    print()
    print(f"[*] Packet details:")
    print(f"    Type:          0x01 (HANDSHAKE_INIT)")
    print(f"    SenderIndex:   0x{sender_index:08X}")
    print(f"    Total size:    {len(pkt)} bytes (structurally valid)")
    print()
    print(f"[*] All crypto fields are random garbage:")
    print(f"    Ephemeral key: {bytes(pkt[8:16]).hex()}... (not a valid X25519 point)")
    print(f"    MAC1:          {bytes(pkt[116:124]).hex()}... (not BLAKE2b of real data)")
    print()
    print(f"[*] Watch server logs for: [WARN] MAC1 verification failed")
    print()

    sock.sendto(bytes(pkt), target)
    print(f"[*] Sent 148-byte corrupt HANDSHAKE_INIT packet.")
    print(f"[*] Screenshot the server WARN line.")

    sock.close()


if __name__ == "__main__":
    main()
