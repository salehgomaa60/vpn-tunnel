#include "test_runner.h"
#include "../src/packet.h"
#include "../src/config.h"
#include "../src/logging.h"
#include <errno.h>

static void test_handshake_init_parser(void) {
    packet_handshake_init_t src, dst;
    uint8_t wire[PACKET_HANDSHAKE_INIT_LEN + 16];

    memset(&src, 0, sizeof(src));
    src.sender_index = 0x12345678;
    memset(src.unencrypted_ephemeral, 0xAA, sizeof(src.unencrypted_ephemeral));
    memset(src.encrypted_static, 0xBB, sizeof(src.encrypted_static));
    memset(src.encrypted_timestamp, 0xCC, sizeof(src.encrypted_timestamp));
    memset(src.mac1, 0xDD, sizeof(src.mac1));
    memset(src.mac2, 0xEE, sizeof(src.mac2));

    /* Serialize */
    int len = packet_serialize_handshake_init(wire, sizeof(wire), &src);
    TEST_ASSERT(len == PACKET_HANDSHAKE_INIT_LEN, "Serialized length must be 148");

    /* Peek type */
    TEST_ASSERT(packet_peek_type(wire, len) == PACKET_TYPE_HANDSHAKE_INIT,
                "Peek type must return HANDSHAKE_INIT");

    /* Parse */
    TEST_ASSERT(packet_parse_handshake_init(wire, len, &dst) == 0,
                "Valid packet parse must succeed");
    TEST_ASSERT(dst.sender_index == 0x12345678, "Sender index must match");
    TEST_ASSERT_MEM_EQ(dst.unencrypted_ephemeral, src.unencrypted_ephemeral, 32, "Ephemeral pubkey mismatch");
    TEST_ASSERT_MEM_EQ(dst.encrypted_static, src.encrypted_static, 48, "Encrypted static mismatch");
    TEST_ASSERT_MEM_EQ(dst.encrypted_timestamp, src.encrypted_timestamp, 28, "Timestamp mismatch");
    TEST_ASSERT_MEM_EQ(dst.mac1, src.mac1, 16, "MAC1 mismatch");
    TEST_ASSERT_MEM_EQ(dst.mac2, src.mac2, 16, "MAC2 mismatch");

    /* Defensive: Truncated frame */
    TEST_ASSERT(packet_parse_handshake_init(wire, len - 1, &dst) == -EBADMSG,
                "Truncated handshake init must fail with -EBADMSG");

    /* Defensive: Oversized frame */
    TEST_ASSERT(packet_parse_handshake_init(wire, len + 1, &dst) == -EBADMSG,
                "Oversized handshake init must fail with -EBADMSG");

    /* Defensive: Bad packet type */
    wire[0] = 0xFF;
    TEST_ASSERT(packet_parse_handshake_init(wire, len, &dst) == -EBADMSG,
                "Invalid packet type must fail with -EBADMSG");

    /* Defensive: NULL pointers */
    TEST_ASSERT(packet_parse_handshake_init(NULL, len, &dst) == -EINVAL,
                "NULL buffer must return -EINVAL");
}

static void test_handshake_resp_parser(void) {
    packet_handshake_resp_t src, dst;
    uint8_t wire[PACKET_HANDSHAKE_RESP_LEN + 16];

    memset(&src, 0, sizeof(src));
    src.sender_index = 0x11223344;
    src.receiver_index = 0x55667788;
    memset(src.unencrypted_ephemeral, 0x11, sizeof(src.unencrypted_ephemeral));
    memset(src.encrypted_nothing, 0x22, sizeof(src.encrypted_nothing));
    memset(src.mac1, 0x33, sizeof(src.mac1));
    memset(src.mac2, 0x44, sizeof(src.mac2));

    /* Serialize */
    int len = packet_serialize_handshake_resp(wire, sizeof(wire), &src);
    TEST_ASSERT(len == PACKET_HANDSHAKE_RESP_LEN, "Serialized length must be 92");

    /* Peek type */
    TEST_ASSERT(packet_peek_type(wire, len) == PACKET_TYPE_HANDSHAKE_RESP,
                "Peek type must return HANDSHAKE_RESP");

    /* Parse */
    TEST_ASSERT(packet_parse_handshake_resp(wire, len, &dst) == 0,
                "Valid packet parse must succeed");
    TEST_ASSERT(dst.sender_index == 0x11223344, "Sender index must match");
    TEST_ASSERT(dst.receiver_index == 0x55667788, "Receiver index must match");
    TEST_ASSERT_MEM_EQ(dst.unencrypted_ephemeral, src.unencrypted_ephemeral, 32, "Ephemeral mismatch");
    TEST_ASSERT_MEM_EQ(dst.encrypted_nothing, src.encrypted_nothing, 16, "Encrypted empty mismatch");

    /* Defensive: Truncated frame */
    TEST_ASSERT(packet_parse_handshake_resp(wire, len - 1, &dst) == -EBADMSG,
                "Truncated handshake resp must fail with -EBADMSG");

    /* Defensive: Bad type */
    wire[0] = 0x05;
    TEST_ASSERT(packet_parse_handshake_resp(wire, len, &dst) == -EBADMSG,
                "Bad type must fail with -EBADMSG");
}

static void test_data_packet_parser(void) {
    uint8_t wire[PACKET_DATA_MAX_LEN + 32];
    uint8_t payload[100];
    uint8_t auth_tag[VPN_AUTH_TAG_LEN];
    packet_data_t parsed;

    memset(payload, 0x5A, sizeof(payload));
    memset(auth_tag, 0x7E, sizeof(auth_tag));
    uint32_t receiver_idx = 0xDEADBEEF;
    uint64_t counter = 0x0123456789ABCDEFULL;

    /* 1. Standard Data Packet with payload */
    int len = packet_serialize_data(wire, sizeof(wire), receiver_idx, counter,
                                    payload, sizeof(payload), auth_tag);
    TEST_ASSERT(len == (int)(PACKET_DATA_HEADER_LEN + sizeof(payload) + VPN_AUTH_TAG_LEN),
                "Data packet length must match header + payload + tag");

    TEST_ASSERT(packet_peek_type(wire, len) == PACKET_TYPE_DATA, "Peek type must return DATA");

    TEST_ASSERT(packet_parse_data(wire, len, &parsed) == 0, "Parsing data packet must succeed");
    TEST_ASSERT(parsed.receiver_index == receiver_idx, "Receiver index mismatch");
    TEST_ASSERT(parsed.counter == counter, "Counter mismatch");
    TEST_ASSERT(parsed.ciphertext_len == sizeof(payload), "Ciphertext length mismatch");
    TEST_ASSERT_MEM_EQ(parsed.ciphertext, payload, sizeof(payload), "Ciphertext content mismatch");
    TEST_ASSERT_MEM_EQ(parsed.auth_tag, auth_tag, VPN_AUTH_TAG_LEN, "Auth tag mismatch");

    /* 2. Keepalive Packet (0-length payload) */
    int keepalive_len = packet_serialize_data(wire, sizeof(wire), receiver_idx, counter,
                                              NULL, 0, auth_tag);
    TEST_ASSERT(keepalive_len == PACKET_DATA_MIN_LEN, "Keepalive packet must be exactly 32 bytes");
    TEST_ASSERT(packet_peek_type(wire, keepalive_len) == PACKET_TYPE_KEEPALIVE,
                "Peek type must return KEEPALIVE");

    TEST_ASSERT(packet_parse_data(wire, keepalive_len, &parsed) == 0, "Parsing keepalive must succeed");
    TEST_ASSERT(parsed.ciphertext_len == 0, "Keepalive ciphertext len must be 0");
    TEST_ASSERT(parsed.ciphertext == NULL, "Keepalive ciphertext pointer must be NULL");
    TEST_ASSERT_MEM_EQ(parsed.auth_tag, auth_tag, VPN_AUTH_TAG_LEN, "Auth tag mismatch");

    /* 3. Defensive: Truncated frame (< 32 bytes) */
    TEST_ASSERT(packet_parse_data(wire, 31, &parsed) == -EBADMSG,
                "Datagram < 32 bytes must return -EBADMSG");

    /* 4. Defensive: Oversized frame (> 1472 bytes) */
    TEST_ASSERT(packet_parse_data(wire, PACKET_DATA_MAX_LEN + 1, &parsed) == -EMSGSIZE,
                "Datagram > 1472 bytes must return -EMSGSIZE");

    /* 5. Defensive: Invalid packet type */
    wire[0] = 0x99;
    TEST_ASSERT(packet_parse_data(wire, len, &parsed) == -EBADMSG,
                "Invalid packet type must return -EBADMSG");

    /* 6. Maximum 64-bit counter test */
    uint64_t max_counter = 0xFFFFFFFFFFFFFFFFULL;
    packet_serialize_data(wire, sizeof(wire), receiver_idx, max_counter, payload, sizeof(payload), auth_tag);
    packet_parse_data(wire, len, &parsed);
    TEST_ASSERT(parsed.counter == max_counter, "Max 64-bit counter must be preserved");
}

int main(void) {
    printf("=== Phase 4: Packet Format & Parser Tests ===\n");

    TEST_RUN(test_handshake_init_parser);
    TEST_RUN(test_handshake_resp_parser);
    TEST_RUN(test_data_packet_parser);

    TEST_REPORT();
    return 0;
}
