"""
Attack 7: Oversized Packet (MTU Exhaustion / Buffer Boundary Test)
==================================================================
Goal: Send a packet larger than PACKET_DATA_MAX_LEN (1472 bytes).
      The parser rejects it with -EMSGSIZE before any crypto work is done.

Why 1472 bytes?
  Ethernet MTU = 1500 bytes
  Outer IPv4 header = 20 bytes
  Outer UDP header = 8 bytes
  Remaining for VPN payload = 1472 bytes
  → Any VPN DATA packet larger than 1472 would cause IP fragmentation.
  → We reject oversized packets rather than fragment.

Code path:
  transport_recv()    → reads UDP datagram of 1500 bytes
  packet_peek_type()  → type = 0x03 (DATA)
  packet_parse_data() → len=1500 > PACKET_DATA_MAX_LEN=1472 → -EMSGSIZE → DROP

Relevant source:
  src/packet.c line 371-375:
    if (len > PACKET_DATA_MAX_LEN) {   // PACKET_DATA_MAX_LEN = 1472
        LOG_WARN("packet_parse_data: Packet length %zu exceeds maximum %d",
                 len, PACKET_DATA_MAX_LEN);
        return -EMSGSIZE;
    }

Expected server log:
  [WARN] packet_parse_data: Packet length 1500 exceeds maximum 1472

How to run:
  python3 attack7_oversized.py
"""

import socket
import os


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = ("127.0.0.1", 51820)

    # Build a 1500-byte payload starting with type=0x03 (DATA)
    # This is 28 bytes over the maximum of 1472
    payload_size = 1500
    payload = bytes([0x03]) + os.urandom(payload_size - 1)

    print(f"[*] Oversized Packet Attack")
    print(f"[*] Target: {target[0]}:{target[1]}")
    print()
    print(f"[*] Packet details:")
    print(f"    Type:         0x03 (DATA)")
    print(f"    Total size:   {len(payload)} bytes")
    print(f"    Maximum:      1472 bytes")
    print(f"    Excess:       {len(payload) - 1472} bytes over limit")
    print()
    print(f"[*] Watch server logs for: [WARN] packet_parse_data: Packet length 1500 exceeds maximum 1472")
    print()

    sock.sendto(payload, target)
    print(f"[*] Sent {len(payload)}-byte oversized packet.")
    print(f"[*] Screenshot the server WARN line.")

    sock.close()


if __name__ == "__main__":
    main()
