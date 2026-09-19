"""
Attack 3: Replay Attack
========================
Goal: Capture one valid encrypted DATA packet, then resend it 2+ times.
      The first send is processed normally. The second and subsequent sends
      are rejected by the anti-replay sliding window.

Code path:
  First send:
    replay_check()   → counter is new → PASS
    AEAD decrypt     → tag matches → PASS
    replay_update()  → marks counter as seen in bitmap
    Plaintext written to TUN interface

  Second send (same packet):
    replay_check()   → bitmap bit for this counter is SET → return 0 → DROP

Relevant source:
  src/replay.c line 88-89:
    if ((filter->bitmap[word_idx] & (1ULL << bit_idx)) != 0) {
        return 0;  // REPLAY DETECTED — packet dropped
    }

HOW TO CAPTURE A REAL PACKET:
  1. Start server and client
  2. Run: sudo tcpdump -i lo -w /tmp/vpn.pcap udp port 51820
  3. Ping through tunnel: ping -I vpn0 10.0.0.2 -c 1
  4. Stop tcpdump (Ctrl+C)
  5. Extract data packet:
       python3 -c "
         from scapy.all import rdpcap, UDP
         pkts = rdpcap('/tmp/vpn.pcap')
         payloads = [bytes(p[UDP].payload) for p in pkts if UDP in p]
         data = [p for p in payloads if len(p) >= 32 and p[0] == 0x03]
         if data:
             open('/tmp/captured.bin', 'wb').write(data[0])
             print(f'Saved {len(data[0])} bytes')
       "
  6. Then run: python3 attack3_replay.py

Expected server log:
  [INFO ] Processed data packet counter=N
  [WARN ] replay_check: counter N already seen — dropping packet
  [WARN ] replay_check: counter N already seen — dropping packet

How to run:
  python3 attack3_replay.py
"""

import socket
import time
import os
import sys


def main():
    capture_file = "/tmp/captured.bin"

    if not os.path.exists(capture_file):
        print("[!] No captured packet found.")
        print("[!] Follow the HOW TO CAPTURE section in this script's docstring.")
        print("[!] Then re-run: python3 attack3_replay.py")
        sys.exit(1)

    with open(capture_file, "rb") as f:
        captured_packet = f.read()

    if len(captured_packet) < 32:
        print(f"[!] Captured packet too short ({len(captured_packet)} bytes). Needs to be >= 32.")
        sys.exit(1)

    # Print packet analysis
    pkt_type    = captured_packet[0]
    recv_index  = int.from_bytes(captured_packet[4:8], 'little')
    counter     = int.from_bytes(captured_packet[8:16], 'little')

    print(f"[*] Captured packet analysis:")
    print(f"    Type:           0x{pkt_type:02x} ({'DATA' if pkt_type == 0x03 else 'UNKNOWN'})")
    print(f"    ReceiverIndex:  {recv_index} (0x{recv_index:08X})")
    print(f"    Counter:        {counter} (0x{counter:016X})")
    print(f"    Total size:     {len(captured_packet)} bytes")
    print(f"    Ciphertext len: {len(captured_packet) - 32} bytes")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = ("127.0.0.1", 51820)

    print(f"[*] Target: {target[0]}:{target[1]}")
    print(f"[*] Watch server logs for ACCEPT on #1 and REPLAY DROP on #2/#3")
    print()

    # Send #1 — server should accept
    sock.sendto(captured_packet, target)
    print(f"[1] Sent packet (counter={counter}) — expect: ACCEPTED by server")
    time.sleep(0.3)

    # Send #2 — same exact bytes, replay_check() must reject
    sock.sendto(captured_packet, target)
    print(f"[2] Sent same packet again (counter={counter}) — expect: REPLAY DROPPED")
    time.sleep(0.3)

    # Send #3 — still the same packet
    sock.sendto(captured_packet, target)
    print(f"[3] Sent same packet again (counter={counter}) — expect: REPLAY DROPPED")

    sock.close()
    print()
    print("[*] Done. Screenshot the server log showing #1 accepted, #2 and #3 dropped.")


if __name__ == "__main__":
    main()
