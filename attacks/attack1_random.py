"""
Attack 1: Unauthenticated Random Bytes
======================================
Goal: Send completely random garbage to the server's UDP port.

Code path:
  1. transport_recv()      — receives the raw bytes
  2. packet_peek_type()    — reads buf[0], sees unknown type byte
  3. Returns PACKET_TYPE_INVALID → main loop drops packet

Expected server log:
  [WARN] packet_peek_type: Invalid packet type 0xXX

How to run:
  python3 attack1_random.py
"""

import socket
import os


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = ("127.0.0.1", 51820)

    print(f"[*] Sending 10 random-byte packets to {target[0]}:{target[1]}")
    print(f"[*] Watch server logs for: [WARN] packet_peek_type: Invalid packet type")
    print()

    for i in range(10):
        payload = os.urandom(64)   # 64 completely random bytes, no valid structure
        sock.sendto(payload, target)
        print(f"  [{i+1:02d}] Sent 64 random bytes — first byte: 0x{payload[0]:02x}")

    sock.close()
    print()
    print("[*] Done. Screenshot the server WARN lines now.")


if __name__ == "__main__":
    main()
