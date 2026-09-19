/*
 * kdf.c — Key Derivation Functions
 *
 * PURPOSE
 * -------
 * The handshake needs to derive multiple independent symmetric keys from
 * shared DH secrets.  We cannot use the raw DH output directly because:
 *
 *   1. DH output has some algebraic structure — it is the x-coordinate of
 *      an elliptic curve point, not a uniformly random 32-byte string.
 *   2. We need MORE than one key from a single DH operation (e.g. both a
 *      send_key and a recv_key from the final chaining key).
 *
 * HOW THE KDF WORKS (HKDF-like construction using BLAKE2b)
 * ---------------------------------------------------------
 *
 * STEP 1 — EXTRACT:
 *   PRK = BLAKE2b-256(key=chaining_key, msg=dh_output)
 *
 *   The chaining_key acts as the HMAC key.  The DH output is the input
 *   material.  The result, PRK (Pseudo-Random Key), is a uniformly random
 *   32-byte value.
 *
 * STEP 2 — EXPAND:
 *   out1 = BLAKE2b-256(key=PRK, msg=0x01)
 *   out2 = BLAKE2b-256(key=PRK, msg=out1 || 0x02)
 *   out3 = BLAKE2b-256(key=PRK, msg=out2 || 0x03)
 *
 *   The counter byte (0x01, 0x02, 0x03) ensures each output is
 *   cryptographically independent even though they share the same PRK.
 *
 * This is essentially HKDF (RFC 5869) but using BLAKE2b instead of
 * HMAC-SHA-256.  WireGuard uses the identical construction with BLAKE2s.
 *
 * RELATIONSHIP TO THE HANDSHAKE
 * ------------------------------
 *   KDF1(ck, dh) → new_ck
 *       Used when only the chaining key needs to advance (mix a DH result
 *       into the key schedule without producing a usable key yet).
 *
 *   KDF2(ck, dh) → (new_ck, temp_key)
 *       Used when we need both an updated chaining key AND a temporary
 *       encryption key for the next AEAD step.
 *
 *   KDF3(ck, empty) → (new_ck, send_key, recv_key)
 *       Used at the end of the handshake to produce the two directional
 *       transport keys.  In practice we use KDF2 with empty input for this.
 */

#include "kdf.h"
#include "crypto.h"
#include <sodium.h>
#include <string.h>


/* =========================================================================
 * vpn_kdf1
 *
 * Derive ONE output from the chaining key and input material.
 *
 * INPUTS
 * ------
 *   key[32]      : current chaining key (ck).  Acts as BLAKE2b key.
 *   input        : DH output or public key bytes being mixed in.
 *   input_len    : length of input.
 *
 * OUTPUTS
 * -------
 *   out1[32]     : new chaining key.  Overwrites key[] position.
 *
 * INTERNAL:
 *   PRK  = BLAKE2b(key=key,  msg=input)    — Extract
 *   out1 = BLAKE2b(key=PRK,  msg=0x01)     — Expand T1
 * ========================================================================= */
void vpn_kdf1(uint8_t out1[VPN_KEY_LEN],
              const uint8_t key[VPN_KEY_LEN],
              const uint8_t *input, size_t input_len) {
    /*
     * PRK = keyed-BLAKE2b(input, key=key)
     * The chaining key is the MAC key; the DH result is the input message.
     * This "extracts" structured DH output into a uniformly random PRK.
     */
    uint8_t prk[VPN_KEY_LEN];
    crypto_generichash(prk, sizeof(prk),
                       input, (unsigned long long)input_len,
                       key, VPN_KEY_LEN);

    /*
     * out1 = keyed-BLAKE2b(0x01, key=PRK)
     * Counter byte 0x01 is the entire message — we are just labelling this
     * output "the first expansion".
     */
    uint8_t byte1 = 0x01;
    crypto_generichash(out1, VPN_KEY_LEN,
                       &byte1, 1,
                       prk, sizeof(prk));

    /* Wipe intermediate PRK — it could be used to derive future keys */
    vpn_crypto_memzero(prk, sizeof(prk));
}


/* =========================================================================
 * vpn_kdf2
 *
 * Derive TWO outputs from the chaining key and input material.
 *
 * INPUTS
 * ------
 *   key[32]      : current chaining key.
 *   input        : DH output or NULL (for the final transport key step).
 *   input_len    : length of input (0 is valid).
 *
 * OUTPUTS
 * -------
 *   out1[32]     : new chaining key.
 *   out2[32]     : temporary AEAD key for the next encrypt/decrypt step,
 *                  OR transport send/recv key at the end of handshake.
 *
 * INTERNAL:
 *   PRK  = BLAKE2b(key=key,  msg=input)         — Extract
 *   out1 = BLAKE2b(key=PRK,  msg=0x01)           — Expand T1
 *   out2 = BLAKE2b(key=PRK,  msg=out1 || 0x02)   — Expand T2
 * ========================================================================= */
void vpn_kdf2(uint8_t out1[VPN_KEY_LEN],
              uint8_t out2[VPN_KEY_LEN],
              const uint8_t key[VPN_KEY_LEN],
              const uint8_t *input, size_t input_len) {
    uint8_t prk[VPN_KEY_LEN];
    crypto_generichash(prk, sizeof(prk),
                       input, (unsigned long long)input_len,
                       key, VPN_KEY_LEN);

    /* T1: first expansion output — new chaining key */
    uint8_t byte1 = 0x01;
    crypto_generichash(out1, VPN_KEY_LEN,
                       &byte1, 1,
                       prk, sizeof(prk));

    /*
     * T2: second expansion output — built by hashing T1 concatenated with
     * the counter byte 0x02.  The T1 prefix binds T2 to T1, so T1 and T2
     * are computationally independent from each other's preimage.
     *
     * Wire layout of buf: [ out1[0..31] | 0x02 ]
     */
    uint8_t buf[VPN_KEY_LEN + 1];
    memcpy(buf, out1, VPN_KEY_LEN);
    buf[VPN_KEY_LEN] = 0x02;
    crypto_generichash(out2, VPN_KEY_LEN,
                       buf, sizeof(buf),
                       prk, sizeof(prk));

    vpn_crypto_memzero(prk, sizeof(prk));
    vpn_crypto_memzero(buf, sizeof(buf));
}


/* =========================================================================
 * vpn_kdf3
 *
 * Derive THREE outputs from the chaining key and input material.
 *
 * Currently used in principle but in practice the handshake only needs
 * KDF2 at the end.  This function is here for completeness and to support
 * an optional PSK (Pre-Shared Key) mixing step where out3 would be the
 * PSK-mixed key.
 *
 * INTERNAL:
 *   PRK  = BLAKE2b(key=key,  msg=input)
 *   out1 = BLAKE2b(key=PRK,  msg=0x01)
 *   out2 = BLAKE2b(key=PRK,  msg=out1 || 0x02)
 *   out3 = BLAKE2b(key=PRK,  msg=out2 || 0x03)
 * ========================================================================= */
void vpn_kdf3(uint8_t out1[VPN_KEY_LEN],
              uint8_t out2[VPN_KEY_LEN],
              uint8_t out3[VPN_KEY_LEN],
              const uint8_t key[VPN_KEY_LEN],
              const uint8_t *input, size_t input_len) {
    uint8_t prk[VPN_KEY_LEN];
    crypto_generichash(prk, sizeof(prk),
                       input, (unsigned long long)input_len,
                       key, VPN_KEY_LEN);

    uint8_t byte1 = 0x01;
    crypto_generichash(out1, VPN_KEY_LEN, &byte1, 1, prk, sizeof(prk));

    uint8_t buf[VPN_KEY_LEN + 1];
    memcpy(buf, out1, VPN_KEY_LEN);
    buf[VPN_KEY_LEN] = 0x02;
    crypto_generichash(out2, VPN_KEY_LEN, buf, sizeof(buf), prk, sizeof(prk));

    /* T3: hash of T2 || 0x03 */
    memcpy(buf, out2, VPN_KEY_LEN);
    buf[VPN_KEY_LEN] = 0x03;
    crypto_generichash(out3, VPN_KEY_LEN, buf, sizeof(buf), prk, sizeof(prk));

    vpn_crypto_memzero(prk, sizeof(prk));
    vpn_crypto_memzero(buf, sizeof(buf));
}
