#ifndef VPN_KDF_H
#define VPN_KDF_H

#include <stddef.h>
#include <stdint.h>
#include "config.h"

/**
 * KDF1: Derive 1 key from chaining key and input material using BLAKE2b HKDF construction.
 */
void vpn_kdf1(uint8_t out1[VPN_KEY_LEN],
              const uint8_t key[VPN_KEY_LEN],
              const uint8_t *input, size_t input_len);

/**
 * KDF2: Derive 2 keys from chaining key and input material.
 */
void vpn_kdf2(uint8_t out1[VPN_KEY_LEN],
              uint8_t out2[VPN_KEY_LEN],
              const uint8_t key[VPN_KEY_LEN],
              const uint8_t *input, size_t input_len);

/**
 * KDF3: Derive 3 keys from chaining key and input material.
 */
void vpn_kdf3(uint8_t out1[VPN_KEY_LEN],
              uint8_t out2[VPN_KEY_LEN],
              uint8_t out3[VPN_KEY_LEN],
              const uint8_t key[VPN_KEY_LEN],
              const uint8_t *input, size_t input_len);

#endif /* VPN_KDF_H */
