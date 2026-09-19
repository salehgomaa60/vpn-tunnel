#include "test_runner.h"
#include "../src/handshake.h"
#include "../src/kdf.h"
#include "../src/crypto.h"
#include "../src/config.h"
#include "../src/logging.h"
#include <errno.h>

static void test_kdf_functions(void) {
    uint8_t key[VPN_KEY_LEN] = {0x01, 0x02, 0x03, 0x04};
    uint8_t input[32] = {0xAA, 0xBB, 0xCC, 0xDD};

    uint8_t out1[VPN_KEY_LEN], out2[VPN_KEY_LEN], out3[VPN_KEY_LEN];

    /* Test KDF1 */
    vpn_kdf1(out1, key, input, sizeof(input));
    uint8_t zeroes[VPN_KEY_LEN] = {0};
    TEST_ASSERT(vpn_crypto_memcmp(out1, zeroes, VPN_KEY_LEN) != 0, "KDF1 output must not be zeroes");

    /* Test KDF2 */
    vpn_kdf2(out1, out2, key, input, sizeof(input));
    TEST_ASSERT(vpn_crypto_memcmp(out1, out2, VPN_KEY_LEN) != 0, "KDF2 outputs must be distinct");

    /* Test KDF3 */
    vpn_kdf3(out1, out2, out3, key, input, sizeof(input));
    TEST_ASSERT(vpn_crypto_memcmp(out1, out2, VPN_KEY_LEN) != 0, "KDF3 out1 and out2 must differ");
    TEST_ASSERT(vpn_crypto_memcmp(out2, out3, VPN_KEY_LEN) != 0, "KDF3 out2 and out3 must differ");
}

static void test_full_handshake_exchange(void) {
    /* 1. Setup Alice (Initiator) and Bob (Responder) Keypairs */
    uint8_t alice_pub[VPN_PUBKEY_LEN], alice_priv[VPN_PRIVKEY_LEN];
    uint8_t bob_pub[VPN_PUBKEY_LEN], bob_priv[VPN_PRIVKEY_LEN];
    vpn_crypto_generate_keypair(alice_pub, alice_priv);
    vpn_crypto_generate_keypair(bob_pub, bob_priv);

    vpn_peer_table_t bob_peer_table;
    peer_table_init(&bob_peer_table);
    peer_add(&bob_peer_table, "alice", alice_pub, NULL);

    /* 2. Alice creates Handshake Initiation */
    uint8_t init_packet[PACKET_HANDSHAKE_INIT_LEN];
    handshake_init_state_t alice_state;
    uint32_t alice_local_idx = 100;

    int init_len = handshake_create_initiation(init_packet, sizeof(init_packet),
                                               alice_priv, alice_pub, bob_pub,
                                               alice_local_idx, &alice_state);
    TEST_ASSERT(init_len == PACKET_HANDSHAKE_INIT_LEN, "Initiation packet size must be 148");

    /* 3. Bob consumes Handshake Initiation */
    vpn_peer_t *authenticated_peer = NULL;
    packet_handshake_init_t parsed_init;
    uint8_t bob_chaining_key[VPN_KEY_LEN];
    uint8_t bob_hash[32];

    int consume_init_rc = handshake_consume_initiation(init_packet, sizeof(init_packet),
                                                       bob_priv, bob_pub,
                                                       &bob_peer_table,
                                                       &authenticated_peer,
                                                       &parsed_init,
                                                       bob_chaining_key, bob_hash);
    TEST_ASSERT(consume_init_rc == 0, "Bob consuming initiation must succeed");
    TEST_ASSERT(authenticated_peer != NULL && strcmp(authenticated_peer->name, "alice") == 0,
                "Authenticated peer must be Alice");

    /* 4. Bob creates Handshake Response */
    uint8_t resp_packet[PACKET_HANDSHAKE_RESP_LEN];
    uint32_t bob_local_idx = 200;
    uint8_t bob_send_key[VPN_KEY_LEN], bob_recv_key[VPN_KEY_LEN];

    int resp_len = handshake_create_response(resp_packet, sizeof(resp_packet),
                                             bob_priv,
                                             parsed_init.unencrypted_ephemeral,
                                             authenticated_peer->public_key,
                                             bob_local_idx,
                                             parsed_init.sender_index,
                                             bob_chaining_key, bob_hash,
                                             bob_send_key, bob_recv_key);
    TEST_ASSERT(resp_len == PACKET_HANDSHAKE_RESP_LEN, "Response packet size must be 92");

    /* 5. Alice consumes Handshake Response */
    uint32_t alice_derived_peer_idx = 0;
    uint8_t alice_send_key[VPN_KEY_LEN], alice_recv_key[VPN_KEY_LEN];

    int consume_resp_rc = handshake_consume_response(resp_packet, sizeof(resp_packet),
                                                     alice_priv,
                                                     &alice_state,
                                                     bob_pub,
                                                     &alice_derived_peer_idx,
                                                     alice_send_key, alice_recv_key);
    TEST_ASSERT(consume_resp_rc == 0, "Alice consuming response must succeed");
    TEST_ASSERT(alice_derived_peer_idx == bob_local_idx, "Derived peer index must match Bob's local index");

    /* 6. Verify Directional Key Cross-Symmetry:
     * Alice Send Key == Bob Recv Key
     * Alice Recv Key == Bob Send Key */
    TEST_ASSERT_MEM_EQ(alice_send_key, bob_recv_key, VPN_KEY_LEN,
                       "Alice SEND key must match Bob RECV key");
    TEST_ASSERT_MEM_EQ(alice_recv_key, bob_send_key, VPN_KEY_LEN,
                       "Alice RECV key must match Bob SEND key");

    /* 7. Verify Bidirectional AEAD Transmission with Derived Session Keys */
    const uint8_t msg_to_bob[] = "Ping from Alice to Bob";
    uint8_t c_to_bob[128], tag_to_bob[16], pt_at_bob[128];

    vpn_crypto_aead_encrypt(c_to_bob, tag_to_bob, msg_to_bob, sizeof(msg_to_bob), NULL, 0, 0, alice_send_key);
    int dec_at_bob = vpn_crypto_aead_decrypt(pt_at_bob, c_to_bob, sizeof(msg_to_bob), tag_to_bob, NULL, 0, 0, bob_recv_key);
    TEST_ASSERT(dec_at_bob == 0, "Bob must decrypt message using bob_recv_key");
    TEST_ASSERT_MEM_EQ(pt_at_bob, msg_to_bob, sizeof(msg_to_bob), "Decrypted text at Bob must match");

    const uint8_t msg_to_alice[] = "Pong from Bob to Alice";
    uint8_t c_to_alice[128], tag_to_alice[16], pt_at_alice[128];

    vpn_crypto_aead_encrypt(c_to_alice, tag_to_alice, msg_to_alice, sizeof(msg_to_alice), NULL, 0, 0, bob_send_key);
    int dec_at_alice = vpn_crypto_aead_decrypt(pt_at_alice, c_to_alice, sizeof(msg_to_alice), tag_to_alice, NULL, 0, 0, alice_recv_key);
    TEST_ASSERT(dec_at_alice == 0, "Alice must decrypt reply using alice_recv_key");
    TEST_ASSERT_MEM_EQ(pt_at_alice, msg_to_alice, sizeof(msg_to_alice), "Decrypted text at Alice must match");

    /* Clean up sensitive keys */
    peer_table_destroy(&bob_peer_table);
    vpn_crypto_memzero(alice_priv, sizeof(alice_priv));
    vpn_crypto_memzero(bob_priv, sizeof(bob_priv));
    vpn_crypto_memzero(alice_send_key, sizeof(alice_send_key));
    vpn_crypto_memzero(alice_recv_key, sizeof(alice_recv_key));
    vpn_crypto_memzero(bob_send_key, sizeof(bob_send_key));
    vpn_crypto_memzero(bob_recv_key, sizeof(bob_recv_key));
}

static void test_handshake_rejection_unknown_peer(void) {
    uint8_t eve_pub[VPN_PUBKEY_LEN], eve_priv[VPN_PRIVKEY_LEN];
    uint8_t bob_pub[VPN_PUBKEY_LEN], bob_priv[VPN_PRIVKEY_LEN];
    vpn_crypto_generate_keypair(eve_pub, eve_priv);
    vpn_crypto_generate_keypair(bob_pub, bob_priv);

    /* Bob's table only knows Alice, NOT Eve */
    vpn_peer_table_t bob_table;
    peer_table_init(&bob_table);
    uint8_t alice_pub[VPN_PUBKEY_LEN] = {0x11};
    peer_add(&bob_table, "alice", alice_pub, NULL);

    uint8_t init_packet[PACKET_HANDSHAKE_INIT_LEN];
    handshake_init_state_t eve_state;
    handshake_create_initiation(init_packet, sizeof(init_packet), eve_priv, eve_pub, bob_pub, 999, &eve_state);

    vpn_peer_t *peer = NULL;
    packet_handshake_init_t parsed;
    uint8_t ck[VPN_KEY_LEN], h[32];
    int rc = handshake_consume_initiation(init_packet, sizeof(init_packet), bob_priv, bob_pub,
                                          &bob_table, &peer, &parsed, ck, h);
    TEST_ASSERT(rc == -EACCES, "Handshake initiation from unknown peer must return -EACCES");

    peer_table_destroy(&bob_table);
    vpn_crypto_memzero(eve_priv, sizeof(eve_priv));
    vpn_crypto_memzero(bob_priv, sizeof(bob_priv));
}

static void test_handshake_rejection_corrupted_message(void) {
    uint8_t alice_pub[VPN_PUBKEY_LEN], alice_priv[VPN_PRIVKEY_LEN];
    uint8_t bob_pub[VPN_PUBKEY_LEN], bob_priv[VPN_PRIVKEY_LEN];
    vpn_crypto_generate_keypair(alice_pub, alice_priv);
    vpn_crypto_generate_keypair(bob_pub, bob_priv);

    vpn_peer_table_t bob_table;
    peer_table_init(&bob_table);
    peer_add(&bob_table, "alice", alice_pub, NULL);

    uint8_t init_packet[PACKET_HANDSHAKE_INIT_LEN];
    handshake_init_state_t state;
    handshake_create_initiation(init_packet, sizeof(init_packet), alice_priv, alice_pub, bob_pub, 123, &state);

    /* Corrupt encrypted static key bytes */
    init_packet[50] ^= 0xFF;

    vpn_peer_t *peer = NULL;
    packet_handshake_init_t parsed;
    uint8_t ck[VPN_KEY_LEN], h[32];
    int rc = handshake_consume_initiation(init_packet, sizeof(init_packet), bob_priv, bob_pub,
                                          &bob_table, &peer, &parsed, ck, h);
    TEST_ASSERT(rc == -EBADMSG, "Corrupted handshake init must fail AEAD authentication with -EBADMSG");

    peer_table_destroy(&bob_table);
    vpn_crypto_memzero(alice_priv, sizeof(alice_priv));
    vpn_crypto_memzero(bob_priv, sizeof(bob_priv));
}

int main(void) {
    printf("=== Phase 7: Handshake & Key Derivation Tests ===\n");
    vpn_crypto_init();

    TEST_RUN(test_kdf_functions);
    TEST_RUN(test_full_handshake_exchange);
    TEST_RUN(test_handshake_rejection_unknown_peer);
    TEST_RUN(test_handshake_rejection_corrupted_message);

    TEST_REPORT();
    return 0;
}
