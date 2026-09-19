#ifndef VPN_PACKET_H
#define VPN_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include "config.h"

/* Packet Types */
typedef enum {
    PACKET_TYPE_INVALID        = 0x00,
    PACKET_TYPE_HANDSHAKE_INIT = 0x01,
    PACKET_TYPE_HANDSHAKE_RESP = 0x02,
    PACKET_TYPE_DATA           = 0x03,
    PACKET_TYPE_KEEPALIVE      = 0x04
} packet_type_t;

/* Exact Fixed Sizes on Wire */
#define PACKET_HANDSHAKE_INIT_LEN   148
#define PACKET_HANDSHAKE_RESP_LEN   92
#define PACKET_DATA_HEADER_LEN      16   /* Type(1) + Reserved(3) + Receiver(4) + Counter(8) */
#define PACKET_DATA_MIN_LEN         (PACKET_DATA_HEADER_LEN + VPN_AUTH_TAG_LEN) /* 32 bytes */
#define PACKET_DATA_MAX_PAYLOAD     VPN_DEFAULT_INNER_MTU                      /* 1440 bytes */
#define PACKET_DATA_MAX_LEN         (PACKET_DATA_MIN_LEN + PACKET_DATA_MAX_PAYLOAD) /* 1472 bytes */

/* Handshake Initiation Wire Structure */
typedef struct {
    uint32_t sender_index;
    uint8_t  unencrypted_ephemeral[VPN_PUBKEY_LEN];
    uint8_t  encrypted_static[VPN_PUBKEY_LEN + VPN_AUTH_TAG_LEN]; /* 32 + 16 = 48 */
    uint8_t  encrypted_timestamp[12 + VPN_AUTH_TAG_LEN];          /* 12 + 16 = 28 */
    uint8_t  mac1[16];
    uint8_t  mac2[16];
} packet_handshake_init_t;

/* Handshake Response Wire Structure */
typedef struct {
    uint32_t sender_index;
    uint32_t receiver_index;
    uint8_t  unencrypted_ephemeral[VPN_PUBKEY_LEN];
    uint8_t  encrypted_nothing[VPN_AUTH_TAG_LEN];                 /* 16 bytes */
    uint8_t  mac1[16];
    uint8_t  mac2[16];
} packet_handshake_resp_t;

/* Data / Keepalive Packet Parsed View (zero-copy pointers into buffer) */
typedef struct {
    uint32_t receiver_index;
    uint64_t counter;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    const uint8_t *auth_tag;
} packet_data_t;

/* Little-Endian Safe Helpers */
static inline uint32_t le32_read(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           (((uint32_t)p[1]) << 8) |
           (((uint32_t)p[2]) << 16) |
           (((uint32_t)p[3]) << 24);
}

static inline void le32_write(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline uint64_t le64_read(const uint8_t *p) {
    return ((uint64_t)p[0]) |
           (((uint64_t)p[1]) << 8) |
           (((uint64_t)p[2]) << 16) |
           (((uint64_t)p[3]) << 24) |
           (((uint64_t)p[4]) << 32) |
           (((uint64_t)p[5]) << 40) |
           (((uint64_t)p[6]) << 48) |
           (((uint64_t)p[7]) << 56);
}

static inline void le64_write(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
    p[4] = (uint8_t)((v >> 32) & 0xFF);
    p[5] = (uint8_t)((v >> 40) & 0xFF);
    p[6] = (uint8_t)((v >> 48) & 0xFF);
    p[7] = (uint8_t)((v >> 56) & 0xFF);
}

/**
 * Peek at packet type byte with minimum length check.
 */
packet_type_t packet_peek_type(const uint8_t *buf, size_t len);

/**
 * Parse a Handshake Initiation packet.
 * Validates length == 148, type == 0x01, and extracts fields into `out`.
 */
int packet_parse_handshake_init(const uint8_t *buf, size_t len, packet_handshake_init_t *out);

/**
 * Serialize a Handshake Initiation packet into destination buffer.
 */
int packet_serialize_handshake_init(uint8_t *buf, size_t buf_size, const packet_handshake_init_t *msg);

/**
 * Parse a Handshake Response packet.
 * Validates length == 92, type == 0x02, and extracts fields into `out`.
 */
int packet_parse_handshake_resp(const uint8_t *buf, size_t len, packet_handshake_resp_t *out);

/**
 * Serialize a Handshake Response packet into destination buffer.
 */
int packet_serialize_handshake_resp(uint8_t *buf, size_t buf_size, const packet_handshake_resp_t *msg);

/**
 * Parse a Data or Keepalive packet.
 * Validates length >= 32 and <= 1472, type == 0x03 or 0x04.
 */
int packet_parse_data(const uint8_t *buf, size_t len, packet_data_t *out);

/**
 * Serialize a Data packet header, ciphertext payload, and authentication tag into buffer.
 */
int packet_serialize_data(uint8_t *buf, size_t buf_size, uint32_t receiver_index,
                          uint64_t counter, const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *auth_tag);

#endif /* VPN_PACKET_H */
