/*
 * crypto.c — Cryptographic Primitives Layer
 *
 * PURPOSE
 * -------
 * This file wraps libsodium's raw APIs into simpler, named functions that
 * match the vocabulary of our VPN tunnel.  Everything cryptographic that
 * the rest of the tunnel does passes through here — there is no raw call to
 * <sodium.h> outside this file (and kdf.c which also documents itself).
 *
 * LIBRARY USED: libsodium (https://doc.libsodium.org/)
 * We chose libsodium because:
 *   - It provides audited, side-channel-resistant implementations.
 *   - It defaults to the same cipher suite that WireGuard uses.
 *   - It avoids the footgun of raw OpenSSL EVP.
 *
 * CIPHER SUITE SUMMARY
 * --------------------
 *   Key Exchange : X25519   (Curve25519 Diffie-Hellman)
 *   AEAD Cipher  : ChaCha20-Poly1305 (IETF variant, 96-bit nonce)
 *   Hash / MAC   : BLAKE2b  (used as the KDF base and transcript hash)
 *   Nonce        : 12 bytes = 4 zero bytes || 8-byte counter (Little-Endian)
 *   Key Length   : 32 bytes (256 bits) for everything
 *   Auth Tag     : 16 bytes (128-bit Poly1305)
 */

#include "crypto.h"
#include "packet.h"       /* for le64_write() */
#include "logging.h"
#include <sodium.h>
#include <string.h>
#include <errno.h>

/*
 * g_dummy_byte — a single static zero byte used as a non-NULL pointer for
 * zero-length buffer arguments.  libsodium's encrypt/decrypt functions have
 * "nonnull" attributes, which means passing NULL for a zero-length input
 * causes a compiler warning even though the library would never dereference
 * it.  We pass &g_dummy_byte instead.
 */
static const uint8_t g_dummy_byte = 0;


/* =========================================================================
 * vpn_crypto_init
 *
 * WHAT:  Initialise libsodium's runtime.
 *
 * WHY:   libsodium may need to seed its CSPRNG, detect hardware AES support,
 *        or perform other one-time setup.  Calling sodium_init() more than
 *        once is safe — it returns 1 (not 0) on subsequent calls.
 *
 * RETURN:  0 on success.  Negative errno on failure.
 * ========================================================================= */
int vpn_crypto_init(void) {
    /*
     * sodium_init() returns:
     *    0  — successful first initialisation
     *    1  — already initialised (safe to ignore)
     *   -1  — fatal internal error (e.g. OS PRNG is broken)
     */
    if (sodium_init() < 0) {
        LOG_ERROR("vpn_crypto_init: libsodium initialization failed");
        return -EFAULT;
    }
    return 0;
}


/* =========================================================================
 * vpn_crypto_random_bytes
 *
 * WHAT:  Fill a buffer with cryptographically strong random bytes.
 *
 * HOW:   Delegates to randombytes_buf() which uses the OS CSPRNG
 *        (/dev/urandom or getrandom() on Linux).
 *
 * USE CASES inside this VPN:
 *   - Generating ephemeral X25519 private keys during handshake.
 *   - Generating static X25519 private keys at startup.
 *
 * WARNING: Never use rand(), random(), or time() for key material.
 * ========================================================================= */
void vpn_crypto_random_bytes(uint8_t *buf, size_t len) {
    if (buf && len > 0) {
        randombytes_buf(buf, len);
    }
}


/* =========================================================================
 * vpn_crypto_memzero
 *
 * WHAT:  Securely wipe a buffer containing sensitive key material.
 *
 * WHY NOT memset():  A modern optimising compiler is allowed to eliminate a
 * memset() that writes to memory which is never read again — exactly the
 * case when you zero a key buffer just before freeing or leaving scope.
 * sodium_memzero() is implemented using a method that the compiler cannot
 * legally optimise away (e.g. volatile write or SecureZeroMemory on Win32).
 *
 * CALL THIS:
 *   - After each DH shared secret is fed into the KDF.
 *   - After each temporary AEAD key (kappa) is used.
 *   - When a session is destroyed.
 *   - At daemon shutdown for the static private key.
 * ========================================================================= */
void vpn_crypto_memzero(void *p, size_t len) {
    if (p && len > 0) {
        sodium_memzero(p, len);
    }
}


/* =========================================================================
 * vpn_crypto_memcmp
 *
 * WHAT:  Compare two byte buffers in constant time.
 *
 * WHY:   A naive C memcmp() returns early at the first differing byte.
 *        If an attacker can measure how long your comparison took, they can
 *        binary-search for the correct value — this is a "timing side-channel".
 *        sodium_memcmp() always touches every byte regardless of where the
 *        mismatch is.
 *
 * RETURN:  0 if identical, non-zero if different.
 * ========================================================================= */
int vpn_crypto_memcmp(const void *b1, const void *b2, size_t len) {
    if (!b1 || !b2) {
        return -1;
    }
    return sodium_memcmp(b1, b2, len);
}


/* =========================================================================
 * vpn_crypto_format_nonce
 *
 * WHAT:  Build the 12-byte IETF AEAD nonce from a 64-bit packet counter.
 *
 * NONCE LAYOUT (12 bytes):
 *   Bytes  0-3  : 0x00 0x00 0x00 0x00   (four zero bytes / upper 32 bits)
 *   Bytes  4-11 : counter, 8 bytes, Little-Endian
 *
 * EXAMPLE — counter = 1:
 *   nonce = 00 00 00 00  01 00 00 00 00 00 00 00
 *                         ^^ this is byte index 4
 *
 * EXAMPLE — counter = 256 (0x100):
 *   nonce = 00 00 00 00  00 01 00 00 00 00 00 00
 *
 * WHY THIS LAYOUT:
 *   WireGuard uses exactly this nonce structure.  The counter is in the
 *   lower 64 bits of the 96-bit nonce, matching the IETF ChaCha20-Poly1305
 *   nonce format (RFC 8439).
 *
 * UNIQUENESS GUARANTEE:
 *   Each packet gets a different nonce because the counter increments by 1
 *   per packet.  The sending_counter field in vpn_session_t is the source.
 *   Counter 0 is used for the handshake's AEAD operations (which have
 *   different keys, so there is no nonce collision).
 *
 * INPUT:  counter — the 64-bit packet sequence number.
 * OUTPUT: nonce[VPN_NONCE_LEN] — 12 bytes, caller-allocated.
 *         This buffer belongs to the caller.  We write all 12 bytes.
 * ========================================================================= */
void vpn_crypto_format_nonce(uint64_t counter, uint8_t nonce[VPN_NONCE_LEN]) {
    /* Zero the first 4 bytes */
    memset(nonce, 0, 4);
    /*
     * Write the 64-bit counter in Little-Endian order into bytes 4..11.
     * le64_write() from packet.h does:
     *   p[0] = counter & 0xFF;
     *   p[1] = (counter >> 8) & 0xFF;
     *   ...
     *   p[7] = (counter >> 56) & 0xFF;
     */
    le64_write(nonce + 4, counter);
}


/* =========================================================================
 * vpn_crypto_aead_encrypt
 *
 * WHAT:  Encrypt plaintext and produce a separate 16-byte auth tag.
 *
 * ALGORITHM: ChaCha20-Poly1305 IETF (detached mode)
 *   - ChaCha20 is a stream cipher — it XORs a keystream with the plaintext.
 *   - Poly1305 is a one-time MAC — it authenticates the ciphertext + AD.
 *   - "Detached" means the auth tag is returned separately (not appended).
 *     We store the tag separately in the wire packet so the parser can
 *     point at both without copying.
 *
 * INPUTS
 * ------
 *   ciphertext    : caller-allocated output buffer, >= plaintext_len bytes.
 *                   Controlled by us (the sender).  May be NULL if
 *                   plaintext_len == 0 (keepalive).
 *   mac[16]       : caller-allocated output for the 16-byte Poly1305 tag.
 *                   Controlled by us.
 *   plaintext     : the raw IP packet read from the TUN device.
 *                   Controlled by our kernel (trusted).
 *   plaintext_len : number of bytes in plaintext (0 for keepalive).
 *   ad / ad_len   : Additional Data — authenticated but NOT encrypted.
 *                   Typically the handshake transcript hash.
 *                   May be NULL / 0 for transport data packets.
 *   counter       : monotonically increasing 64-bit sequence number.
 *                   Converted to nonce internally by vpn_crypto_format_nonce().
 *   key[32]       : the session's send_key.  Never logged.
 *
 * OUTPUTS
 * -------
 *   ciphertext    : plaintext XORed with ChaCha20 keystream.
 *   mac[16]       : Poly1305 authentication tag over (ciphertext || AD).
 *
 * RETURN:  0 on success.  -EINVAL for bad arguments.  -EFAULT for crypto failure.
 *
 * KEY FACT: ciphertext is the same length as plaintext.  ChaCha20 is a
 * stream cipher, NOT a block cipher, so there is no padding.
 * ========================================================================= */
int vpn_crypto_aead_encrypt(uint8_t *ciphertext,
                            uint8_t mac[VPN_AUTH_TAG_LEN],
                            const uint8_t *plaintext,
                            size_t plaintext_len,
                            const uint8_t *ad,
                            size_t ad_len,
                            uint64_t counter,
                            const uint8_t key[VPN_KEY_LEN]) {
    if (!mac || !key) {
        return -EINVAL;
    }
    if (plaintext_len > 0 && (!ciphertext || !plaintext)) {
        return -EINVAL;
    }

    /* Build the 12-byte nonce on the stack.  It is wiped after use. */
    uint8_t nonce[VPN_NONCE_LEN];
    vpn_crypto_format_nonce(counter, nonce);

    /*
     * Workaround for compiler nonnull attribute warnings:
     * If len == 0, the crypto call won't dereference the pointer, but
     * the compiler might still warn.  Point at a dummy byte instead.
     */
    const uint8_t *p_in  = (plaintext_len > 0) ? plaintext         : &g_dummy_byte;
    uint8_t       *c_out = (plaintext_len > 0) ? ciphertext         : (uint8_t *)&g_dummy_byte;
    const uint8_t *ad_in = (ad_len > 0)        ? ad                 : &g_dummy_byte;

    unsigned long long mac_len = 0;

    /*
     * crypto_aead_chacha20poly1305_ietf_encrypt_detached() — libsodium
     *
     * Parameters (in order):
     *   c          out: ciphertext (same length as m)
     *   mac        out: 16-byte authentication tag
     *   mac_len    out: always set to 16 (Poly1305 tag length)
     *   m          in:  plaintext (may be same pointer as c — in-place)
     *   mlen       in:  length of plaintext in bytes
     *   ad         in:  additional authenticated data (NOT encrypted)
     *   adlen      in:  length of additional data
     *   nsec       in:  NULL (no secret nonce — not used in IETF variant)
     *   npub       in:  12-byte public nonce (our counter-derived nonce)
     *   k          in:  32-byte symmetric key
     */
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        c_out,
        mac,
        &mac_len,
        p_in,
        (unsigned long long)plaintext_len,
        ad_in,
        (unsigned long long)ad_len,
        NULL,       /* nsec: not used */
        nonce,
        key
    );

    /* Wipe the stack nonce — it is derived from the counter but still
     * sensitive since it commits us to a nonce-key pair. */
    vpn_crypto_memzero(nonce, sizeof(nonce));

    if (rc != 0 || mac_len != VPN_AUTH_TAG_LEN) {
        LOG_ERROR("vpn_crypto_aead_encrypt: Encryption failed (rc=%d)", rc);
        return -EFAULT;
    }

    return 0;
}


/* =========================================================================
 * vpn_crypto_aead_decrypt
 *
 * WHAT:  Verify the Poly1305 tag and, ONLY IF it matches, decrypt.
 *
 * CRITICAL ORDERING:
 *   Authentication happens BEFORE decryption.  The plaintext output buffer
 *   is NOT written if authentication fails.  This prevents "decrypt-and-check"
 *   patterns that open the door to padding oracle and other CCA attacks.
 *
 * INPUTS
 * ------
 *   plaintext       : caller-allocated output, >= ciphertext_len bytes.
 *                     We WRITE to this ONLY after auth succeeds.
 *                     May be NULL if ciphertext_len == 0.
 *   ciphertext      : raw encrypted bytes from the network.  UNTRUSTED.
 *   ciphertext_len  : number of encrypted bytes.  UNTRUSTED.
 *   mac[16]         : 16-byte Poly1305 tag from the packet.  UNTRUSTED.
 *   ad / ad_len     : additional data that must match what the sender used.
 *   counter         : the packet sequence number (from wire header).  UNTRUSTED.
 *                     Used to rebuild the same nonce the sender used.
 *   key[32]         : the session's recv_key.
 *
 * OUTPUTS
 * -------
 *   plaintext       : decrypted IP packet, only written on success.
 *
 * RETURN:
 *    0         — authentication and decryption succeeded.
 *   -EINVAL    — bad parameters.
 *   -EBADMSG   — Poly1305 verification failed (wrong key, tampered
 *                ciphertext, wrong counter, wrong AD, or replay).
 *
 * THREAT MODEL:
 *   All inputs except key[] are completely under attacker control.
 *   The only thing protecting us is that the attacker cannot forge a valid
 *   Poly1305 tag without knowing the key.  Probability of random forgery is
 *   approximately 2^-106 per attempt.
 * ========================================================================= */
int vpn_crypto_aead_decrypt(uint8_t *plaintext,
                            const uint8_t *ciphertext,
                            size_t ciphertext_len,
                            const uint8_t mac[VPN_AUTH_TAG_LEN],
                            const uint8_t *ad,
                            size_t ad_len,
                            uint64_t counter,
                            const uint8_t key[VPN_KEY_LEN]) {
    if (!mac || !key) {
        return -EINVAL;
    }
    if (ciphertext_len > 0 && (!ciphertext || !plaintext)) {
        return -EINVAL;
    }

    uint8_t nonce[VPN_NONCE_LEN];
    vpn_crypto_format_nonce(counter, nonce);

    uint8_t       *p_out = (ciphertext_len > 0) ? plaintext         : (uint8_t *)&g_dummy_byte;
    const uint8_t *c_in  = (ciphertext_len > 0) ? ciphertext        : &g_dummy_byte;
    const uint8_t *ad_in = (ad_len > 0)         ? ad                : &g_dummy_byte;

    /*
     * crypto_aead_chacha20poly1305_ietf_decrypt_detached() — libsodium
     *
     * Internally it:
     *   1. Re-derives the Poly1305 one-time key from (key, nonce).
     *   2. Computes Poly1305(ciphertext || ad, one_time_key).
     *   3. Compares the computed tag against mac[] in CONSTANT TIME.
     *   4. Only if step 3 passes: decrypts ciphertext into plaintext.
     *
     * If step 3 fails (mismatch), the function returns -1 and plaintext
     * is left untouched.
     */
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        p_out,
        NULL,       /* nsec: not used */
        c_in,
        (unsigned long long)ciphertext_len,
        mac,        /* the attacker-supplied tag we are verifying */
        ad_in,
        (unsigned long long)ad_len,
        nonce,
        key
    );

    vpn_crypto_memzero(nonce, sizeof(nonce));

    if (rc != 0) {
        /* -1 from libsodium means "tag verification failed" */
        return -EBADMSG;
    }

    return 0;
}


/* =========================================================================
 * vpn_crypto_generate_keypair
 *
 * WHAT:  Generate a fresh X25519 key pair.
 *
 * X25519 is Curve25519 Diffie-Hellman:
 *   - Private key: 32 random bytes, then clamped (bits 0,1,2,255 forced).
 *     Clamping is done internally by libsodium to ensure the scalar is
 *     in the correct range for the Curve25519 group.
 *   - Public key: scalar-multiplication of private key by the base point G.
 *     public_key = private_key * G  (on Curve25519)
 *
 * crypto_box_keypair() uses X25519 (Curve25519) internally.
 *
 * INPUTS:  none (generates fresh randomness)
 * OUTPUTS:
 *   public_key[32]  — safe to transmit unencrypted during handshake.
 *   private_key[32] — MUST be kept secret.  Wipe with vpn_crypto_memzero()
 *                     after use.
 * ========================================================================= */
int vpn_crypto_generate_keypair(uint8_t public_key[VPN_PUBKEY_LEN],
                                uint8_t private_key[VPN_PRIVKEY_LEN]) {
    if (!public_key || !private_key) {
        return -EINVAL;
    }
    if (crypto_box_keypair(public_key, private_key) != 0) {
        LOG_ERROR("vpn_crypto_generate_keypair: Key generation failed");
        return -EFAULT;
    }
    return 0;
}


/* =========================================================================
 * vpn_crypto_dh
 *
 * WHAT:  Perform X25519 Diffie-Hellman scalar multiplication.
 *
 * OPERATION:
 *   shared_secret = my_private_key * their_public_key
 *
 * This is the core of the key exchange.  The magic is:
 *   Alice computes:  alice_priv * bob_pub  = alice_priv * (bob_priv * G)
 *   Bob computes:    bob_priv  * alice_pub = bob_priv  * (alice_priv * G)
 *   Both arrive at:  alice_priv * bob_priv * G  — the same point.
 *
 * The shared_secret is the x-coordinate of that curve point.  It is then
 * fed into the KDF (not used directly as a key) because raw DH output has
 * some statistical structure we want to remove.
 *
 * INPUTS:
 *   their_public_key[32] — received from the network.  UNTRUSTED.
 *                          If the attacker sends a low-order point, the DH
 *                          output can be predictable.  Curve25519 clamping
 *                          mitigates this but does not eliminate all cases.
 *   my_private_key[32]   — our own secret.  Trusted.
 *
 * OUTPUTS:
 *   shared_secret[32]    — raw DH output.  WIPE IMMEDIATELY after use.
 *
 * RETURN:  0 on success.  -EBADMSG if the public key was rejected (e.g.
 *          all-zero point, which is a degenerate low-order element).
 *          libsodium's crypto_scalarmult() checks for this and returns -1.
 * ========================================================================= */
int vpn_crypto_dh(uint8_t shared_secret[VPN_KEY_LEN],
                  const uint8_t their_public_key[VPN_PUBKEY_LEN],
                  const uint8_t my_private_key[VPN_PRIVKEY_LEN]) {
    if (!shared_secret || !their_public_key || !my_private_key) {
        return -EINVAL;
    }
    /*
     * crypto_scalarmult(q, n, p):
     *   q = n * p   (Curve25519 scalar multiplication)
     *   n = private scalar (my_private_key)
     *   p = public point  (their_public_key)
     *   q = shared secret  (x-coordinate of result)
     */
    if (crypto_scalarmult(shared_secret, my_private_key, their_public_key) != 0) {
        LOG_WARN("vpn_crypto_dh: Scalar multiplication failed (invalid public key)");
        return -EBADMSG;
    }
    return 0;
}


/* =========================================================================
 * vpn_crypto_hash
 *
 * WHAT:  Compute a 32-byte BLAKE2b digest of the input.
 *
 * Used for:
 *   - Initialising the handshake chaining key from the protocol identifier.
 *   - Mixing data into the transcript hash (mix_hash in handshake.c).
 *   - Computing MAC key material (hash(label || public_key)).
 *
 * BLAKE2b is a fast, secure cryptographic hash with:
 *   - 256-bit output (32 bytes here)
 *   - No length-extension vulnerability (unlike SHA-1 / SHA-256)
 *   - Designed to be faster than MD5 on modern CPUs
 *
 * INPUTS:
 *   in[in_len]  — the data to hash.  May be any length.
 * OUTPUTS:
 *   out[32]     — the hash digest.  Caller-allocated.
 * ========================================================================= */
int vpn_crypto_hash(uint8_t out[32], const uint8_t *in, size_t in_len) {
    if (!out || (!in && in_len > 0)) {
        return -EINVAL;
    }
    const uint8_t *p_in = (in_len > 0) ? in : &g_dummy_byte;
    /*
     * crypto_generichash(out, outlen, in, inlen, key, keylen)
     * With key=NULL, keylen=0 this is an unkeyed BLAKE2b hash.
     */
    if (crypto_generichash(out, 32, p_in, (unsigned long long)in_len, NULL, 0) != 0) {
        return -EFAULT;
    }
    return 0;
}


/* =========================================================================
 * vpn_crypto_mac16
 *
 * WHAT:  Compute a 16-byte keyed BLAKE2b MAC.
 *
 * This is BLAKE2b in its keyed (PRF) mode.  It is used to produce MAC1
 * in the handshake packets — a lightweight integrity check on the
 * unencrypted ephemeral public key, computed using the responder's
 * static public key as the MAC key.
 *
 * INPUTS:
 *   key[key_len]  — the MAC key.  Typically hash(their_static_pubkey).
 *   in[in_len]    — the data to authenticate.
 * OUTPUTS:
 *   out[16]       — 16-byte MAC.  Caller-allocated.
 * ========================================================================= */
int vpn_crypto_mac16(uint8_t out[16], const uint8_t *key, size_t key_len,
                     const uint8_t *in, size_t in_len) {
    if (!out || !key || key_len == 0 || (!in && in_len > 0)) {
        return -EINVAL;
    }
    const uint8_t *p_in = (in_len > 0) ? in : &g_dummy_byte;
    /*
     * crypto_generichash() with a key = keyed BLAKE2b.
     * Output is truncated to 16 bytes instead of the full 32/64.
     */
    if (crypto_generichash(out, 16, p_in, (unsigned long long)in_len, key, key_len) != 0) {
        return -EFAULT;
    }
    return 0;
}
