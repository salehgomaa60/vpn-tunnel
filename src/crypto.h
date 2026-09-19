#ifndef VPN_CRYPTO_H
#define VPN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "config.h"

/**
 * Initialize libsodium runtime. Safe to call multiple times.
 * @return 0 on success, negative error code on failure.
 */
int vpn_crypto_init(void);

/**
 * Securely fill buffer with cryptographically strong random bytes.
 */
void vpn_crypto_random_bytes(uint8_t *buf, size_t len);

/**
 * Securely wipe sensitive memory (guaranteed not to be optimized away).
 */
void vpn_crypto_memzero(void *p, size_t len);

/**
 * Constant-time memory comparison to prevent timing side-channels.
 * @return 0 if buffers are identical, non-zero otherwise.
 */
int vpn_crypto_memcmp(const void *b1, const void *b2, size_t len);

/**
 * Construct the 12-byte IETF AEAD nonce from a 64-bit counter:
 * 4 bytes of zeroes + 8 bytes of counter in Little-Endian.
 */
void vpn_crypto_format_nonce(uint64_t counter, uint8_t nonce[VPN_NONCE_LEN]);

/**
 * Encrypt plaintext using ChaCha20-Poly1305 AEAD with detached authentication tag.
 * 
 * @param ciphertext     Output buffer for ciphertext (must be >= plaintext_len).
 * @param mac            Output 16-byte Poly1305 authentication tag.
 * @param plaintext      Input plaintext data.
 * @param plaintext_len  Length of plaintext data.
 * @param ad             Optional authenticated additional data (or NULL).
 * @param ad_len         Length of additional data (or 0).
 * @param counter        64-bit packet sequence counter (used for nonce).
 * @param key            32-byte symmetric session key.
 * @return               0 on success, negative error code on failure.
 */
int vpn_crypto_aead_encrypt(uint8_t *ciphertext,
                            uint8_t mac[VPN_AUTH_TAG_LEN],
                            const uint8_t *plaintext,
                            size_t plaintext_len,
                            const uint8_t *ad,
                            size_t ad_len,
                            uint64_t counter,
                            const uint8_t key[VPN_KEY_LEN]);

/**
 * Decrypt ciphertext and verify Poly1305 authentication tag BEFORE exposing plaintext.
 * 
 * @param plaintext       Output buffer for plaintext (must be >= ciphertext_len).
 * @param ciphertext      Input ciphertext data.
 * @param ciphertext_len  Length of ciphertext data.
 * @param mac             Input 16-byte Poly1305 authentication tag.
 * @param ad              Optional authenticated additional data (or NULL).
 * @param ad_len          Length of additional data (or 0).
 * @param counter         64-bit packet sequence counter.
 * @param key             32-byte symmetric session key.
 * @return                0 on success (authenticated), -EBADMSG on authentication failure, -EINVAL on bad params.
 */
int vpn_crypto_aead_decrypt(uint8_t *plaintext,
                            const uint8_t *ciphertext,
                            size_t ciphertext_len,
                            const uint8_t mac[VPN_AUTH_TAG_LEN],
                            const uint8_t *ad,
                            size_t ad_len,
                            uint64_t counter,
                            const uint8_t key[VPN_KEY_LEN]);

/**
 * Generate an X25519 public/private keypair.
 */
int vpn_crypto_generate_keypair(uint8_t public_key[VPN_PUBKEY_LEN],
                                uint8_t private_key[VPN_PRIVKEY_LEN]);

/**
 * Perform Diffie-Hellman scalar multiplication (X25519) to compute shared secret.
 */
int vpn_crypto_dh(uint8_t shared_secret[VPN_KEY_LEN],
                  const uint8_t their_public_key[VPN_PUBKEY_LEN],
                  const uint8_t my_private_key[VPN_PRIVKEY_LEN]);

/**
 * BLAKE2b Generic Hash (32-byte digest).
 */
int vpn_crypto_hash(uint8_t out[32], const uint8_t *in, size_t in_len);

/**
 * Keyed BLAKE2b MAC (16-byte tag for handshake cookies/headers).
 */
int vpn_crypto_mac16(uint8_t out[16], const uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len);

#endif /* VPN_CRYPTO_H */
