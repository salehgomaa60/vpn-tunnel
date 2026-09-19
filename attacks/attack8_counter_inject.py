"""
Attack 8: Counter Injection (Replay Window Poisoning Attempt)
=============================================================
Goal: Send DATA packets with very large counters (near UINT64_MAX) to attempt
      to "jump" the sliding window forward and cause legitimate future packets
      to be considered "too old" (outside the 2048-packet window).

WHY THIS DOESN'T WORK — The Two-Phase Replay Invariant:
  The critical security property of our replay filter is:
    1. replay_check()  is called BEFORE AEAD decryption  (pre-check only)
    2. AEAD decryption is performed
    3. replay_update() is called ONLY AFTER AEAD succeeds

  So when we send a packet with counter=0xFFFFFF00:
    - replay_check() → counter > last_counter → PASS (it's "new")
    - AEAD decrypt   → tag mismatch → FAIL → return error
    - replay_update() → NOT CALLED (we never reach this line)
    - Result: last_counter and bitmap are UNCHANGED

  If replay_update() were called BEFORE decryption (broken design):
    - The window would jump by 0xFFFFFF00 slots
    - All legitimate packets with small counters would then appear "too old"
    - This would be a Denial-of-Service vulnerability

  Our implementation correctly does NOT have this bug.

Relevant source:
  src/replay.c lines 19-31 (the educational comment in the file):
    "AEAD Decryption is performed.
     If decryption fails -> tag mismatch, packet dropped, filter unchanged.
     replay_update() is called ONLY AFTER AEAD decryption succeeds."

Expected server log:
  For each injected packet:
    [INFO ] replay_check: counter 0xFFFFFF00 passes (new counter)
    [WARN ] AEAD decryption failed — authentication tag mismatch
    [NOTE ] replay_update() NOT called — window unchanged

After the attack, legitimate packets with small counters still work.

How to run:
  python3 attack8_counter_inject.py
"""

import socket
import struct
import os
import time


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = ("127.0.0.1", 51820)

    # Large counters designed to jump the replay window massively
    # if replay_update() were called before AEAD (which would be a bug)
    attack_counters = [
        0xFFFFFF00,
        0xFFFFFF01,
        0xFFFFFF02,
        0xFFFFFF03,
        0xFFFFFF04,
    ]

    print(f"[*] Counter Injection Attack (Replay Window Poisoning Attempt)")
    print(f"[*] Target: {target[0]}:{target[1]}")
    print()
    print(f"[*] Sending {len(attack_counters)} packets with huge counters...")
    print(f"[*] If the implementation is correct, the replay window will NOT move.")
    print(f"[*] Watch for AEAD failure before any state update.")
    print()

    for counter in attack_counters:
        # Build a minimum 32-byte DATA packet with the huge counter
        #   header (16 bytes): type + reserved + receiver_index + counter
        #   auth_tag (16 bytes): fake random tag
        receiver_index = 1   # assume session 1 exists (may get "unknown index" too)
        header = struct.pack("<BxxxIQ",
                             0x03,            # type = DATA
                             receiver_index,   # receiver_index
                             counter)          # HUGE counter

        fake_auth_tag = os.urandom(16)
        packet = header + fake_auth_tag  # 16 + 16 = 32 bytes

        sock.sendto(packet, target)
        print(f"  Sent counter=0x{counter:016X} -> expect: replay_check PASS, then AEAD FAIL")
        time.sleep(0.1)

    print()
    print(f"[*] All {len(attack_counters)} injected packets sent.")
    print()
    print(f"[*] Now verify the window was NOT corrupted:")
    print(f"    If you have the client running, try pinging through the tunnel.")
    print(f"    Legitimate packets with small counters should still be accepted.")
    print()
    print(f"[*] Screenshot the server log showing:")
    print(f"    - AEAD failure for each injected packet")
    print(f"    - Legitimate traffic still flowing after the attack")

    sock.close()


if __name__ == "__main__":
    main()
