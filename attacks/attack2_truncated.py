"""
Attack 2: Truncated / Malformed DATA Packet
============================================
Goal: Send a packet with a valid type byte (0x03 = DATA) but
      with only 10 bytes total. The minimum is 32 bytes (16-byte
      header + 16-byte auth tag). The parser rejects it immediately.

Code path:
  1. transport_recv()         — receives the UDP payload
  2. packet_peek_type()       — returns PACKET_TYPE_DATA (0x03)
  3. packet_parse_data()      — len=10 < PACKET_DATA_MIN_LEN=32 → -EBADMSG

Relevant source:
  src/packet.c line 360-363:
    if (len < PACKET_DATA_MIN_LEN) {
        LOG_WARN("packet_parse_data: Packet length %zu is smaller than minimum %d", ...);
        return -EBADMSG;
    }

Expected server log:
  [WARN] packet_parse_data: Packet length 10 is smaller than minimum 32

How to run:
  python3 attack2_truncated.py
"""

import socket
import struct


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = ("127.0.0.1", 51820)

    # Build a 10-byte packet:
    #   byte 0:   type = 0x03 (DATA) — valid type byte, passes peek_type
    #   bytes 1-3: reserved = 0x00 0x00 0x00
    #   bytes 4-7: receiver_index = 1 (LE32)
    #   bytes 8-9: partial counter — we STOP here (only 10 bytes total)
    # Result: packet_parse_data sees len=10, minimum is 32 → REJECTED
    short_packet = bytes([
        0x03,              # type = DATA
        0x00, 0x00, 0x00,  # reserved
        0x01, 0x00, 0x00, 0x00,  # receiver_index = 1 (LE32)
        0x00, 0x00         # partial counter (truncated — only 10 bytes total)
    ])

    print(f"[*] Sending truncated DATA packet to {target[0]}:{target[1]}")
    print(f"[*] Packet size: {len(short_packet)} bytes (minimum required: 32)")
    print(f"[*] Hex: {short_packet.hex()}")
    print(f"[*] Watch server logs for: [WARN] packet_parse_data: Packet length 10 is smaller than minimum 32")
    print()

    sock.sendto(short_packet, target)
    print("[*] Sent. Screenshot the server WARN line now.")

    sock.close()


if __name__ == "__main__":
    main()
