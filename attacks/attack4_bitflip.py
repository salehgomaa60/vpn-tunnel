"""
Attack 4: Bit-Flip Attack on Ciphertext (AEAD Integrity Test)
=============================================================
Goal: Take a captured valid encrypted DATA packet and flip exactly one bit
      in the ciphertext body. ChaCha20-Poly1305 must detect this tampering
      via the Poly1305 authentication tag and drop the packet.

What this proves:
  Authenticated Encryption = Confidentiality + Integrity + Authenticity.
  Even a single bit change in the ciphertext causes the 128-bit Poly1305
  tag to be completely wrong. The decryption fails before any plaintext
  is produced.

Code path:
  replay_check()           → PASS (counter not yet seen)
  vpn_crypto_aead_decrypt() → Poly1305 tag mismatch → return -1 → DROP
  replay_update()          → NOT CALLED (never reached)

Note: The original valid packet would be accepted. The bit-flipped version
      looks identical at the network layer but the crypto layer rejects it.

Prerequisites: Same as attack3 — you need /tmp/captured.bin

How to run:
  python3 attack4_bitflip.py
"""

import socket
import os
import sys


def main():
    capture_file = "/tmp/captured.bin"

    if not os.path.exists(capture_file):
        print("[!] No captured packet found at /tmp/captured.bin")
        print("[!] Run attack3_replay.py capture steps first.")
        sys.exit(1)

    with open(capture_file, "rb") as f:
        original = f.read()

    if len(original) < 33:
        print(f"[!] Packet too short to have ciphertext ({len(original)} bytes).")
        sys.exit(1)

    # Make a mutable copy
    modified = bytearray(original)

    # Wire layout:
    #   bytes  0-15:  header (type, reserved, receiver_index, counter)
    #   bytes 16..N-17: ciphertext body
    #   bytes N-16..N-1: 16-byte Poly1305 auth tag
    #
    # We flip bit 0 of byte at offset 16 (first byte of ciphertext)

    offset = 16   # first ciphertext byte
    before = modified[offset]
    modified[offset] ^= 0x01   # flip the least significant bit
    after  = modified[offset]

    print(f"[*] Bit-Flip Attack on AEAD Ciphertext")
    print(f"[*] Packet size: {len(original)} bytes")
    print()
    print(f"[*] Flipping bit 0 of byte at offset {offset} (first ciphertext byte):")
    print(f"    Before: 0x{before:02x}  ({before:08b})")
    print(f"    After:  0x{after:02x}  ({after:08b})")
    print(f"    Change: one bit (0x{before ^ after:02x})")
    print()
    print(f"[*] The auth tag is still the original — Poly1305 will MISMATCH")
    print(f"[*] Watch server logs for: [WARN] AEAD decryption failed — authentication tag mismatch")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = ("127.0.0.1", 51820)

    sock.sendto(bytes(modified), target)
    print(f"[*] Sent bit-flipped packet to {target[0]}:{target[1]}")
    print(f"[*] Done. Screenshot the server WARN line.")

    sock.close()


if __name__ == "__main__":
    main()
