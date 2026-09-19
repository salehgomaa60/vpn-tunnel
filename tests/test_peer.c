#include "test_runner.h"
#include "../src/peer.h"
#include "../src/crypto.h"
#include "../src/config.h"
#include "../src/logging.h"
#include <errno.h>

static void test_peer_registration_and_lookup(void) {
    vpn_peer_table_t table;
    peer_table_init(&table);

    uint8_t alice_pub[VPN_PUBKEY_LEN], alice_priv[VPN_PRIVKEY_LEN];
    uint8_t bob_pub[VPN_PUBKEY_LEN], bob_priv[VPN_PRIVKEY_LEN];
    vpn_crypto_generate_keypair(alice_pub, alice_priv);
    vpn_crypto_generate_keypair(bob_pub, bob_priv);

    vpn_endpoint_t ep;
    endpoint_parse("192.168.1.50:51820", &ep);

    /* Add Alice */
    vpn_peer_t *p_alice = peer_add(&table, "alice", alice_pub, &ep);
    TEST_ASSERT(p_alice != NULL, "Adding alice must succeed");
    TEST_ASSERT(table.peer_count == 1, "Peer count must be 1");

    /* Add Bob */
    vpn_peer_t *p_bob = peer_add(&table, "bob", bob_pub, NULL);
    TEST_ASSERT(p_bob != NULL, "Adding bob must succeed");
    TEST_ASSERT(table.peer_count == 2, "Peer count must be 2");

    /* Reject Duplicate Alice */
    vpn_peer_t *p_dup = peer_add(&table, "alice2", alice_pub, NULL);
    TEST_ASSERT(p_dup == NULL, "Duplicate public key must be rejected");

    /* Lookup by Public Key */
    TEST_ASSERT(peer_find_by_pubkey(&table, alice_pub) == p_alice, "Lookup alice must return p_alice");
    TEST_ASSERT(peer_find_by_pubkey(&table, bob_pub) == p_bob, "Lookup bob must return p_bob");

    peer_table_destroy(&table);
    vpn_crypto_memzero(alice_priv, sizeof(alice_priv));
    vpn_crypto_memzero(bob_priv, sizeof(bob_priv));
}

static void test_allowed_ips_cryptographic_routing(void) {
    vpn_peer_table_t table;
    peer_table_init(&table);

    uint8_t alice_pub[VPN_PUBKEY_LEN] = {1};
    uint8_t bob_pub[VPN_PUBKEY_LEN] = {2};

    vpn_peer_t *alice = peer_add(&table, "alice", alice_pub, NULL);
    vpn_peer_t *bob = peer_add(&table, "bob", bob_pub, NULL);

    peer_add_allowed_ip(alice, "10.0.0.2/32");
    peer_add_allowed_ip(bob, "10.0.0.3/32");
    peer_add_allowed_ip(bob, "192.168.1.0/24");

    /* Outbound Routing (peer_find_by_dest_ip) */
    uint32_t ip_alice = vpn_ip_parse("10.0.0.2");
    uint32_t ip_bob = vpn_ip_parse("10.0.0.3");
    uint32_t ip_bob_subnet = vpn_ip_parse("192.168.1.50");
    uint32_t ip_unmatched = vpn_ip_parse("8.8.8.8");

    TEST_ASSERT(peer_find_by_dest_ip(&table, ip_alice) == alice, "10.0.0.2 must route to alice");
    TEST_ASSERT(peer_find_by_dest_ip(&table, ip_bob) == bob, "10.0.0.3 must route to bob");
    TEST_ASSERT(peer_find_by_dest_ip(&table, ip_bob_subnet) == bob, "192.168.1.50 must route to bob");
    TEST_ASSERT(peer_find_by_dest_ip(&table, ip_unmatched) == NULL, "8.8.8.8 must route to NULL (DROP)");

    /* Inbound Source Validation (peer_allows_source_ip) */
    TEST_ASSERT(peer_allows_source_ip(alice, ip_alice) == 1, "Alice allows 10.0.0.2");
    TEST_ASSERT(peer_allows_source_ip(alice, ip_bob) == 0, "Alice rejects 10.0.0.3");
    TEST_ASSERT(peer_allows_source_ip(bob, ip_bob_subnet) == 1, "Bob allows 192.168.1.50");

    peer_table_destroy(&table);
}

static void test_session_lifecycle_and_directional_keys(void) {
    vpn_peer_table_t table;
    peer_table_init(&table);

    uint8_t alice_pub[VPN_PUBKEY_LEN] = {0xAA};
    vpn_peer_t *alice = peer_add(&table, "alice", alice_pub, NULL);

    uint8_t send_key1[VPN_KEY_LEN] = {0x11};
    uint8_t recv_key1[VPN_KEY_LEN] = {0x22};
    uint32_t local_idx1 = 1001;
    uint32_t peer_idx1 = 2001;

    /* Initialize Session 1 */
    peer_init_session(alice, local_idx1, peer_idx1, send_key1, recv_key1);
    TEST_ASSERT(alice->current_session.state == SESSION_STATE_ESTABLISHED, "Session 1 must be ESTABLISHED");
    TEST_ASSERT(alice->current_session.sending_counter == 0, "Sending counter must start at 0");

    /* Lookup by receiver index */
    vpn_session_t *s = NULL;
    TEST_ASSERT(peer_find_by_index(&table, local_idx1, &s) == alice, "Index lookup must find alice");
    TEST_ASSERT(s == &alice->current_session, "Returned session must be current_session");

    /* Rekey: Initialize Session 2 */
    uint8_t send_key2[VPN_KEY_LEN] = {0x33};
    uint8_t recv_key2[VPN_KEY_LEN] = {0x44};
    uint32_t local_idx2 = 1002;
    uint32_t peer_idx2 = 2002;

    peer_init_session(alice, local_idx2, peer_idx2, send_key2, recv_key2);
    TEST_ASSERT(alice->current_session.local_index == local_idx2, "Current session index must be 1002");
    TEST_ASSERT(alice->previous_session.local_index == local_idx1, "Previous session index must be 1001");
    TEST_ASSERT(alice->previous_session.state == SESSION_STATE_ESTABLISHED, "Previous session must be preserved");

    /* Both sessions are searchable during rekey transition */
    TEST_ASSERT(peer_find_by_index(&table, local_idx2, &s) == alice && s == &alice->current_session,
                "Current session lookup must succeed");
    TEST_ASSERT(peer_find_by_index(&table, local_idx1, &s) == alice && s == &alice->previous_session,
                "Previous session lookup must succeed");

    /* Destroy session */
    peer_destroy_session(&alice->current_session);
    TEST_ASSERT(alice->current_session.state == SESSION_STATE_NONE, "Destroyed session state must be NONE");

    peer_table_destroy(&table);
}

static void test_endpoint_roaming(void) {
    vpn_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    snprintf(peer.name, sizeof(peer.name), "alice");

    vpn_endpoint_t ep1, ep2;
    endpoint_parse("1.2.3.4:1000", &ep1);
    endpoint_parse("5.6.7.8:2000", &ep2);

    /* Initial learned endpoint */
    peer.endpoint = ep1;

    /* Unchanged packet */
    TEST_ASSERT(peer_update_endpoint(&peer, &ep1) == 0, "Same endpoint must return 0 (unchanged)");

    /* Roamed packet */
    TEST_ASSERT(peer_update_endpoint(&peer, &ep2) == 1, "New endpoint must return 1 (ROAMED)");
    TEST_ASSERT(endpoint_equal(&peer.endpoint, &ep2) == 1, "Recorded endpoint must update to ep2");
}

int main(void) {
    printf("=== Phase 6: Peer & Session State Tests ===\n");
    vpn_crypto_init();

    TEST_RUN(test_peer_registration_and_lookup);
    TEST_RUN(test_allowed_ips_cryptographic_routing);
    TEST_RUN(test_session_lifecycle_and_directional_keys);
    TEST_RUN(test_endpoint_roaming);

    TEST_REPORT();
    return 0;
}
