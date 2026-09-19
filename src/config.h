#ifndef VPN_CONFIG_H
#define VPN_CONFIG_H

#include <stddef.h>
#include <stdint.h>

/* Maximum Transmission Unit and Buffer Constraints */
#define VPN_DEFAULT_OUTER_MTU       1500
#define VPN_WIRE_OVERHEAD           60    /* 20 IP + 8 UDP + 32 WireGuard/AEAD */
#define VPN_DEFAULT_INNER_MTU       (VPN_DEFAULT_OUTER_MTU - VPN_WIRE_OVERHEAD) /* 1440 */
#define VPN_MIN_IPV4_MTU            576

#define VPN_MAX_PACKET_SIZE         2048  /* Maximum safe datagram size buffer */
#define VPN_MAX_PEERS               256   /* Maximum registered peers */
#define VPN_MAX_CIDRS_PER_PEER      64    /* Maximum AllowedIPs CIDRs per peer */

/* Cryptographic Constants (libsodium) */
#define VPN_KEY_LEN                 32    /* 256-bit keys (X25519, ChaCha20-Poly1305) */
#define VPN_PUBKEY_LEN              32    /* 256-bit public key */
#define VPN_PRIVKEY_LEN             32    /* 256-bit private key */
#define VPN_NONCE_LEN               12    /* 96-bit IETF AEAD nonce */
#define VPN_AUTH_TAG_LEN            16    /* 128-bit Poly1305 authentication tag */

/* Protocol Timeouts & Intervals (seconds) */
#define VPN_REKEY_AFTER_TIME_SEC    120   /* 2 minutes */
#define VPN_REJECT_AFTER_TIME_SEC   180   /* 3 minutes */
#define VPN_KEEPALIVE_INTERVAL_SEC  25    /* 25 seconds */

/* Default Network Ports */
#define VPN_DEFAULT_PORT            51820
#define VPN_DEFAULT_TUN_NAME        "vpn0"

/**
 * Parse a 64-character hexadecimal string into a 32-byte binary key.
 */
int config_parse_key_hex(const char *hex_str, uint8_t key[VPN_KEY_LEN]);

/**
 * Format a 32-byte binary key into a 64-character null-terminated hex string.
 */
int config_key_to_hex(const uint8_t key[VPN_KEY_LEN], char hex_str[65]);

#endif /* VPN_CONFIG_H */
