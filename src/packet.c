/*
 * packet.c — Wire Packet Serialisation and Parsing
 *
 * PURPOSE
 * -------
 * This file defines exactly how bytes travel on the UDP wire.  Every
 * field has a fixed position and a fixed size.  There are no variable-
 * length headers, no dynamic allocation, and no pointer chasing.
 *
 * The three packet types on the wire:
 *
 *   1. HANDSHAKE INITIATION  (148 bytes, always exactly 148)
 *   2. HANDSHAKE RESPONSE    (92 bytes,  always exactly 92)
 *   3. DATA / KEEPALIVE      (32..1472 bytes, variable payload)
 *
 * PARSING PHILOSOPHY
 * ------------------
 * Parsers return -EBADMSG for any structural problem (wrong size, wrong
 * type byte).  They do NOT allocate memory.  The data_packet parser uses
 * zero-copy: it stores pointers INTO the caller's buffer rather than
 * copying bytes out.  This means the caller must keep the network buffer
 * alive for as long as the parsed struct is in use.
 *
 * ENDIANNESS
 * ----------
 * All multi-byte integers on the wire are Little-Endian.
 * The le32_read / le32_write / le64_read / le64_write helpers in packet.h
 * handle the byte-swapping explicitly so the code is correct on both
 * little-endian (x86) and big-endian (SPARC, some ARM) hosts.
 *
 * -------------------------------------------------------------------------
 * HANDSHAKE INITIATION — Wire Layout (148 bytes total)
 * -------------------------------------------------------------------------
 *
 *  Offset  Size  Field
 *  ------  ----  -----
 *    0       1   Type byte:       0x01 (HANDSHAKE_INIT)
 *    1       3   Reserved:        0x00 0x00 0x00
 *    4       4   Sender Index:    LE-32, chosen by the initiator
 *    8      32   Unencrypted Ephemeral Public Key (E_i)
 *   40      48   Encrypted Static Public Key  = AEAD(S_i_pub, tag16)
 *   88      28   Encrypted Timestamp          = AEAD(12-byte ts, tag16)
 *  116      16   MAC1: BLAKE2b-16(key=H(S_r_pub), msg=bytes[0..115])
 *  132      16   MAC2: zeros in our implementation (cookie not implemented)
 *  ----     ---
 *  Total:  148
 *
 * -------------------------------------------------------------------------
 * HANDSHAKE RESPONSE — Wire Layout (92 bytes total)
 * -------------------------------------------------------------------------
 *
 *  Offset  Size  Field
 *  ------  ----  -----
 *    0       1   Type byte:       0x02 (HANDSHAKE_RESP)
 *    1       3   Reserved:        0x00 0x00 0x00
 *    4       4   Sender Index:    LE-32, chosen by the responder
 *    8       4   Receiver Index:  LE-32, echoes the initiator's Sender Index
 *   12      32   Unencrypted Ephemeral Public Key (E_r)
 *   44      16   Encrypted Nothing (zero-byte AEAD payload, 16-byte tag only)
 *   60      16   MAC1
 *   76      16   MAC2 (zeros)
 *  ----     ---
 *  Total:   92
 *
 * -------------------------------------------------------------------------
 * DATA / KEEPALIVE — Wire Layout (16 + N + 16 bytes)
 * -------------------------------------------------------------------------
 *
 *  Offset  Size  Field
 *  ------  ----  -----
 *    0       1   Type byte:       0x03 (DATA) or 0x04 (KEEPALIVE)
 *    1       3   Reserved:        0x00 0x00 0x00
 *    4       4   Receiver Index:  LE-32, identifies which session to use
 *    8       8   Counter:         LE-64, the packet sequence number / nonce counter
 *   16       N   Ciphertext:      N bytes of encrypted IP packet  (N=0 for keepalive)
 *  16+N     16   Auth Tag:        16-byte Poly1305 tag
 *  ----     ---
 *  Total:  32 (keepalive) to 1472 (max data)
 *
 * Minimum: N=0 → 16 + 0 + 16 = 32 bytes
 * Maximum: N=1440 → 16 + 1440 + 16 = 1472 bytes
 *   (1440 = 1500 MTU - 20 IP - 8 UDP - 32 VPN overhead)
 */

#include "packet.h"
#include "logging.h"
#include <string.h>
#include <errno.h>


/* =========================================================================
 * packet_peek_type
 *
 * Read the first byte of a packet to determine its type WITHOUT fully
 * parsing it.  The event loop uses this to decide which parser to call.
 *
 * INPUT:
 *   buf[0]  : the type byte.  Attacker-controlled from the network.
 *   len     : must be >= 1.
 *
 * RETURN:
 *   PACKET_TYPE_HANDSHAKE_INIT  (0x01)
 *   PACKET_TYPE_HANDSHAKE_RESP  (0x02)
 *   PACKET_TYPE_DATA            (0x03)
 *   PACKET_TYPE_KEEPALIVE       (0x04)
 *   PACKET_TYPE_INVALID         (0x00) — for any unknown / invalid byte
 * ========================================================================= */
packet_type_t packet_peek_type(const uint8_t *buf, size_t len) {
    if (!buf || len < 1) {
        return PACKET_TYPE_INVALID;
    }

    uint8_t type = buf[0];
    switch (type) {
        case PACKET_TYPE_HANDSHAKE_INIT:
        case PACKET_TYPE_HANDSHAKE_RESP:
        case PACKET_TYPE_DATA:
        case PACKET_TYPE_KEEPALIVE:
            return (packet_type_t)type;
        default:
            return PACKET_TYPE_INVALID;
    }
}


/* =========================================================================
 * packet_parse_handshake_init
 *
 * Parse a Handshake Initiation packet received from the network.
 *
 * INPUT:
 *   buf[len]  : raw UDP payload.  ENTIRELY UNTRUSTED (from network).
 *               The function reads these offsets:
 *                 buf[0]       — type check
 *                 buf[4..7]    — sender_index (LE-32)
 *                 buf[8..39]   — unencrypted_ephemeral (32 bytes)
 *                 buf[40..87]  — encrypted_static (48 bytes)
 *                 buf[88..115] — encrypted_timestamp (28 bytes)
 *                 buf[116..131]— mac1 (16 bytes)
 *                 buf[132..147]— mac2 (16 bytes)
 *   len       : MUST equal exactly 148.  Any other value → -EBADMSG.
 *
 * OUTPUT:
 *   out       : caller-allocated packet_handshake_init_t struct.
 *               All fields are COPIED out of buf[].
 *               The fields are still cryptographically untrusted at this
 *               stage.  Handshake.c will AEAD-decrypt them.
 *
 * RETURN:
 *    0        — structural parse OK (contents NOT yet authenticated).
 *   -EINVAL   — NULL pointer.
 *   -EBADMSG  — wrong length or wrong type byte.
 * ========================================================================= */
int packet_parse_handshake_init(const uint8_t *buf, size_t len, packet_handshake_init_t *out) {
    if (!buf || !out) {
        return -EINVAL;
    }

    /*
     * Strict exact-length check.  We reject BOTH shorter AND longer packets.
     * Shorter: prevents reading beyond the buffer.
     * Longer:  an unexpected extension could be an exploit attempt, or the
     *          packet is simply not a handshake_init.
     */
    if (len != PACKET_HANDSHAKE_INIT_LEN) {
        LOG_WARN("packet_parse_handshake_init: Invalid length %zu (expected %d)",
                 len, PACKET_HANDSHAKE_INIT_LEN);
        return -EBADMSG;
    }

    /* Type byte must be 0x01.  This is the first line of defence. */
    if (buf[0] != PACKET_TYPE_HANDSHAKE_INIT) {
        LOG_WARN("packet_parse_handshake_init: Invalid packet type 0x%02x", buf[0]);
        return -EBADMSG;
    }

    /*
     * Copy all fields into the output struct.
     * bytes 1-3 are reserved (zero) — we ignore them.
     */
    out->sender_index = le32_read(buf + 4);         /* 4 bytes at offset 4  */
    memcpy(out->unencrypted_ephemeral, buf +  8, sizeof(out->unencrypted_ephemeral)); /* 32 bytes */
    memcpy(out->encrypted_static,      buf + 40, sizeof(out->encrypted_static));      /* 48 bytes */
    memcpy(out->encrypted_timestamp,   buf + 88, sizeof(out->encrypted_timestamp));   /* 28 bytes */
    memcpy(out->mac1,                  buf +116, sizeof(out->mac1));                  /* 16 bytes */
    memcpy(out->mac2,                  buf +132, sizeof(out->mac2));                  /* 16 bytes */

    return 0;
}


/* =========================================================================
 * packet_serialize_handshake_init
 *
 * Write a handshake_init_t struct into a flat byte buffer for transmission.
 *
 * INPUT:
 *   msg     : the fully-constructed handshake message.  All fields AEAD-
 *             encrypted by this point (done in handshake.c).
 *   buf_size: must be >= 148.
 *
 * OUTPUT:
 *   buf[148]: the exact 148-byte wire packet ready to be sent via sendto().
 *
 * RETURN:
 *   148    — bytes written.
 *   -EINVAL — NULL or insufficient buffer.
 * ========================================================================= */
int packet_serialize_handshake_init(uint8_t *buf, size_t buf_size,
                                     const packet_handshake_init_t *msg) {
    if (!buf || !msg || buf_size < PACKET_HANDSHAKE_INIT_LEN) {
        return -EINVAL;
    }

    memset(buf, 0, PACKET_HANDSHAKE_INIT_LEN);

    buf[0] = PACKET_TYPE_HANDSHAKE_INIT;   /* byte 0: type = 0x01   */
    /* buf[1..3]: reserved, left as 0x00 by memset above            */
    le32_write(buf + 4,  msg->sender_index);                                   /* 4 bytes  */
    memcpy(buf +  8, msg->unencrypted_ephemeral, sizeof(msg->unencrypted_ephemeral)); /* 32 */
    memcpy(buf + 40, msg->encrypted_static,      sizeof(msg->encrypted_static));      /* 48 */
    memcpy(buf + 88, msg->encrypted_timestamp,   sizeof(msg->encrypted_timestamp));   /* 28 */
    memcpy(buf +116, msg->mac1,                  sizeof(msg->mac1));                  /* 16 */
    memcpy(buf +132, msg->mac2,                  sizeof(msg->mac2));                  /* 16 */

    return PACKET_HANDSHAKE_INIT_LEN; /* 148 */
}


/* =========================================================================
 * packet_parse_handshake_resp
 *
 * Parse a Handshake Response packet received from the network.
 *
 * INPUT:
 *   buf[len]  : raw UDP payload.  UNTRUSTED.
 *               Reads:
 *                 buf[0]      — type check (must be 0x02)
 *                 buf[4..7]   — sender_index (responder's chosen index)
 *                 buf[8..11]  — receiver_index (echoes our sender_index)
 *                 buf[12..43] — unencrypted_ephemeral (32 bytes)
 *                 buf[44..59] — encrypted_nothing (16-byte auth tag only)
 *                 buf[60..75] — mac1 (16 bytes)
 *                 buf[76..91] — mac2 (16 bytes)
 *   len       : MUST equal exactly 92.
 *
 * OUTPUT:
 *   out       : caller-allocated struct.  Fields copied from buf.
 * ========================================================================= */
int packet_parse_handshake_resp(const uint8_t *buf, size_t len, packet_handshake_resp_t *out) {
    if (!buf || !out) {
        return -EINVAL;
    }

    if (len != PACKET_HANDSHAKE_RESP_LEN) {
        LOG_WARN("packet_parse_handshake_resp: Invalid length %zu (expected %d)",
                 len, PACKET_HANDSHAKE_RESP_LEN);
        return -EBADMSG;
    }

    if (buf[0] != PACKET_TYPE_HANDSHAKE_RESP) {
        LOG_WARN("packet_parse_handshake_resp: Invalid packet type 0x%02x", buf[0]);
        return -EBADMSG;
    }

    out->sender_index   = le32_read(buf + 4);
    out->receiver_index = le32_read(buf + 8);
    memcpy(out->unencrypted_ephemeral, buf + 12, sizeof(out->unencrypted_ephemeral)); /* 32 */
    memcpy(out->encrypted_nothing,     buf + 44, sizeof(out->encrypted_nothing));     /* 16 */
    memcpy(out->mac1,                  buf + 60, sizeof(out->mac1));                  /* 16 */
    memcpy(out->mac2,                  buf + 76, sizeof(out->mac2));                  /* 16 */

    return 0;
}


/* =========================================================================
 * packet_serialize_handshake_resp
 *
 * Write a handshake_resp_t struct into a flat byte buffer for transmission.
 *
 * OUTPUT:
 *   buf[92]: the 92-byte wire packet.
 *
 * RETURN: 92 on success, -EINVAL on bad args.
 * ========================================================================= */
int packet_serialize_handshake_resp(uint8_t *buf, size_t buf_size,
                                     const packet_handshake_resp_t *msg) {
    if (!buf || !msg || buf_size < PACKET_HANDSHAKE_RESP_LEN) {
        return -EINVAL;
    }

    memset(buf, 0, PACKET_HANDSHAKE_RESP_LEN);

    buf[0] = PACKET_TYPE_HANDSHAKE_RESP;  /* 0x02 */
    /* bytes 1-3: reserved, 0x00 */
    le32_write(buf + 4,  msg->sender_index);
    le32_write(buf + 8,  msg->receiver_index);
    memcpy(buf + 12, msg->unencrypted_ephemeral, sizeof(msg->unencrypted_ephemeral)); /* 32 */
    memcpy(buf + 44, msg->encrypted_nothing,     sizeof(msg->encrypted_nothing));     /* 16 */
    memcpy(buf + 60, msg->mac1,                  sizeof(msg->mac1));                  /* 16 */
    memcpy(buf + 76, msg->mac2,                  sizeof(msg->mac2));                  /* 16 */

    return PACKET_HANDSHAKE_RESP_LEN; /* 92 */
}


/* =========================================================================
 * packet_parse_data
 *
 * Parse a DATA or KEEPALIVE packet — the most frequently called parser
 * in normal tunnel operation.
 *
 * INPUT:
 *   buf[len]  : raw UDP payload.  ENTIRELY UNTRUSTED (from network).
 *               Every field in the wire header was set by the remote peer.
 *   len       : >= 32 and <= 1472.
 *
 * ZERO-COPY DESIGN:
 *   out->ciphertext points INSIDE buf[] — no data is copied.
 *   out->auth_tag   points INSIDE buf[] at the last 16 bytes.
 *
 *   The caller MUST NOT free or modify buf[] while using out->ciphertext or
 *   out->auth_tag.  Typically buf[] is the global net_buf[] in main.c which
 *   lives for the duration of one event-loop iteration.
 *
 * WIRE LAYOUT INTERPRETATION:
 *   total_len = len
 *   header    = 16 bytes (type + reserved + receiver_index + counter)
 *   auth_tag  = 16 bytes (always the last 16 bytes of the packet)
 *   ciphertext_len = total_len - 16 (header) - 16 (tag) = total_len - 32
 *
 *   So:
 *     ciphertext starts at buf[16]
 *     ciphertext is (len - 32) bytes long
 *     auth_tag starts at buf[len - 16]
 *
 * OUTPUT:
 *   out->receiver_index  : which session this packet belongs to.
 *   out->counter         : the nonce counter for AEAD decryption.
 *   out->ciphertext      : pointer into buf[], (len-32) bytes.
 *   out->ciphertext_len  : length of ciphertext in bytes (0 for keepalive).
 *   out->auth_tag        : pointer into buf[], always 16 bytes.
 *
 * RETURN:
 *    0        — structural parse OK (data NOT yet decrypted/authenticated).
 *   -EINVAL   — NULL pointer.
 *   -EBADMSG  — packet too short (< 32 bytes) or wrong type.
 *   -EMSGSIZE — packet too long (> 1472 bytes).
 * ========================================================================= */
int packet_parse_data(const uint8_t *buf, size_t len, packet_data_t *out) {
    if (!buf || !out) {
        return -EINVAL;
    }

    /*
     * Minimum: 16-byte header + 16-byte auth tag = 32 bytes.
     * A packet shorter than this cannot contain a valid auth tag.
     */
    if (len < PACKET_DATA_MIN_LEN) {
        LOG_WARN("packet_parse_data: Packet length %zu is smaller than minimum %d",
                 len, PACKET_DATA_MIN_LEN);
        return -EBADMSG;
    }

    /*
     * Maximum: 1472 bytes.  A UDP payload larger than this with the VPN
     * wire overhead would exceed the outer link MTU of 1500 bytes, causing
     * IP fragmentation.  We reject rather than fragment.
     */
    if (len > PACKET_DATA_MAX_LEN) {
        LOG_WARN("packet_parse_data: Packet length %zu exceeds maximum %d",
                 len, PACKET_DATA_MAX_LEN);
        return -EMSGSIZE;
    }

    /* Type must be DATA (0x03) or KEEPALIVE (0x04) */
    uint8_t type = buf[0];
    if (type != PACKET_TYPE_DATA && type != PACKET_TYPE_KEEPALIVE) {
        LOG_WARN("packet_parse_data: Invalid packet type 0x%02x", type);
        return -EBADMSG;
    }

    /* buf[1..3]: reserved, ignore. */

    /*
     * Receiver Index (LE-32 at offset 4):
     *   The sender puts OUR local session index here so we can look up
     *   which peer and session this packet belongs to.
     */
    out->receiver_index = le32_read(buf + 4);

    /*
     * Counter (LE-64 at offset 8):
     *   The 64-bit packet sequence number.  Used to:
     *     1. Build the AEAD nonce (via vpn_crypto_format_nonce).
     *     2. Check the replay filter (via replay_check).
     *   This value is UNTRUSTED — an attacker can set it to any value.
     *   The AEAD decryption will fail if the counter doesn't match what
     *   was used to encrypt.
     */
    out->counter = le64_read(buf + 8);

    /*
     * Ciphertext: everything between the 16-byte header and the 16-byte tag.
     * For keepalive packets this is zero bytes.
     */
    size_t ciphertext_len = len - PACKET_DATA_MIN_LEN;
    out->ciphertext_len = ciphertext_len;
    out->ciphertext     = (ciphertext_len > 0) ? (buf + PACKET_DATA_HEADER_LEN) : NULL;

    /*
     * Auth Tag: the last 16 bytes.
     *   This pointer is valid as long as buf[] is alive.
     *   The auth tag was produced by Poly1305 at the sender.
     */
    out->auth_tag = buf + PACKET_DATA_HEADER_LEN + ciphertext_len;

    return 0;
}


/* =========================================================================
 * packet_serialize_data
 *
 * Build a DATA or KEEPALIVE wire packet from a ciphertext and auth tag.
 *
 * Called by the outbound path in main.c AFTER AEAD encryption has been
 * performed.  The encrypted bytes and auth tag are placed contiguously.
 *
 * INPUT:
 *   receiver_index  : the remote peer's session index (peer->current_session.peer_index).
 *   counter         : the packet sequence number (sending_counter).
 *   ciphertext      : encrypted payload.  NULL if ciphertext_len == 0.
 *   ciphertext_len  : 0 for keepalive, 1..1440 for data.
 *   auth_tag[16]    : 16-byte Poly1305 tag from AEAD encryption.
 *
 * OUTPUT:
 *   buf[total_len]  : the complete wire packet.  buf[0] is the type byte.
 *
 * RETURN:  total packet length (>= 32), or negative error.
 * ========================================================================= */
int packet_serialize_data(uint8_t *buf, size_t buf_size, uint32_t receiver_index,
                          uint64_t counter, const uint8_t *ciphertext,
                          size_t ciphertext_len, const uint8_t *auth_tag) {
    if (!buf || !auth_tag) {
        return -EINVAL;
    }
    if (ciphertext_len > 0 && !ciphertext) {
        return -EINVAL;
    }

    size_t total_len = PACKET_DATA_HEADER_LEN + ciphertext_len + VPN_AUTH_TAG_LEN;
    if (buf_size < total_len) {
        return -ENOSPC;
    }

    /* Zero the 16-byte header so reserved bytes are clean */
    memset(buf, 0, PACKET_DATA_HEADER_LEN);

    /*
     * Type byte:
     *   0x04 (KEEPALIVE) if ciphertext_len == 0
     *   0x03 (DATA)      if ciphertext_len >  0
     */
    buf[0] = (ciphertext_len == 0) ? PACKET_TYPE_KEEPALIVE : PACKET_TYPE_DATA;
    /* buf[1..3]: reserved, 0x00 */
    le32_write(buf + 4, receiver_index);   /* bytes 4-7:  receiver index */
    le64_write(buf + 8, counter);          /* bytes 8-15: counter        */

    /* Copy ciphertext body (may be 0 bytes for keepalive) */
    if (ciphertext_len > 0) {
        memcpy(buf + PACKET_DATA_HEADER_LEN, ciphertext, ciphertext_len);
    }

    /* Append the 16-byte Poly1305 auth tag at the end */
    memcpy(buf + PACKET_DATA_HEADER_LEN + ciphertext_len, auth_tag, VPN_AUTH_TAG_LEN);

    return (int)total_len;
}
