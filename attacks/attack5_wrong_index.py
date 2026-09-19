"""
Attack 5: Wrong Receiver Index (Session Hijack Attempt)
=======================================================
Goal: Send a structurally valid 32-byte DATA packet with a receiver_index
      that doesn't match any active session. The main event loop looks up
      the session by index and finds nothing → drops the packet.

Code path:
  packet_peek_type()     → PACKET_TYPE_DATA (0x03)
  packet_parse_data()    → structural parse OK (len=32, type=0x03)
  peer_find_by_index()   → returns NULL (no session with this index)
  main.c event loop      → "Unknown receiver index" → DROP

Relevant source:
  src/packet.c line 391:
    out->receiver_index = le32_read(buf + 4);   // read from untrusted wire
  Then in main.c:
    peer = peer_find_by_index(peers, pkt.receiver_index);
    if (!peer) {
        LOG_WARN("Unknown receiver index 0x%08X — no active session, dropping", ...);
        continue;
    }

Wire layout of the packet we build:
  Byte  0:     0x03 (DATA type)
  Bytes 1-3:   0x00 0x00 0x00 (reserved)
  Bytes 4-7:   0xEF 0xBE 0xAD 0xDE = 0xDEADBEEF in little-endian (fake session index)
  Bytes 8-15:  counter = 1 (LE64)
  Bytes 16-31: 16-byte auth tag (random — AEAD will also fail, but we never get there)

Expected server log:
  [WARN] Unknown receiver index 0xDEADBEEF — no active session found, dropping packet

How to run:
  python3 attack5_wrong_index.py
"""

import socket
import struct
import os


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = ("127.0.0.1", 51820)

    # The fake session index we'll put on the wire
    receiver_index = 0xDEADBEEF
    counter = 1

    # Pack the 16-byte header:
    #   "<" = little-endian
    #   "B" = 1 byte (type = 0x03)
    #   "xxx" = 3 padding bytes (reserved = 0x00)
    #   "I" = 4-byte uint32 (receiver_index)
    #   "Q" = 8-byte uint64 (counter)
    header = struct.pack("<BxxxIQ",
                         0x03,           # type = DATA
                         receiver_index, # fake session index
                         counter)        # counter

    # Append 16 bytes of random auth tag (minimum valid DATA packet = 32 bytes)
    # Even though the AEAD would fail, the index lookup happens before decryption
    auth_tag = os.urandom(16)

    packet = header + auth_tag  # 16 + 16 = 32 bytes (minimum valid length)

    print(f"[*] Wrong Session Index Attack")
    print(f"[*] Target: {target[0]}:{target[1]}")
    print()
    print(f"[*] Packet details:")
    print(f"    Type:           0x03 (DATA)")
    print(f"    ReceiverIndex:  0x{receiver_index:08X} (FAKE — no session has this ID)")
    print(f"    Counter:        {counter}")
    print(f"    Packet size:    {len(packet)} bytes")
    print(f"    Hex: {packet.hex()}")
    print()
    print(f"[*] Watch server logs for: [WARN] Unknown receiver index 0xDEADBEEF")
    print()

    sock.sendto(packet, target)
    print(f"[*] Sent. Screenshot the server WARN line.")

    sock.close()


if __name__ == "__main__":
    main()
