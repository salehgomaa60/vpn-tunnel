#include "test_runner.h"
#include "../src/crypto.h"
#include "../src/config.h"
#include "../src/logging.h"
#include <errno.h>

static void test_nonce_formatting(void) {
    uint8_t nonce[VPN_NONCE_LEN];

    /* Test counter 0 */
    vpn_crypto_format_nonce(0, nonce);
    uint8_t expected_0[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    TEST_ASSERT_MEM_EQ(nonce, expected_0, 12, "Nonce for counter 0 must be 12 zeroes");

    /* Test counter 1 */
    vpn_crypto_format_nonce(1, nonce);
    uint8_t expected_1[12] = {0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};
    TEST_ASSERT_MEM_EQ(nonce, expected_1, 12, "Nonce for counter 1 must be 000000000100000000000000");

    /* Test counter 256 (0x0100) */
    vpn_crypto_format_nonce(256, nonce);
    uint8_t expected_256[12] = {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    TEST_ASSERT_MEM_EQ(nonce, expected_256, 12, "Nonce for counter 256 must be 000000000001000000000000");
}

static void test_aead_encrypt_decrypt_roundtrip(void) {
    uint8_t key[VPN_KEY_LEN];
    vpn_crypto_random_bytes(key, sizeof(key));

    const uint8_t plaintext[] = "Confidential IP datagram through WireGuard AEAD tunnel";
    size_t pt_len = sizeof(plaintext);
    const uint8_t ad[] = "Authenticated Additional Header Data";
    size_t ad_len = sizeof(ad);
    uint64_t counter = 42;

    uint8_t ciphertext[128];
    uint8_t mac[VPN_AUTH_TAG_LEN];
    uint8_t decrypted[128];

    /* 1. Encrypt */
    int enc_rc = vpn_crypto_aead_encrypt(ciphertext, mac, plaintext, pt_len, ad, ad_len, counter, key);
    TEST_ASSERT(enc_rc == 0, "AEAD encryption must succeed");

    /* 2. Decrypt */
    int dec_rc = vpn_crypto_aead_decrypt(decrypted, ciphertext, pt_len, mac, ad, ad_len, counter, key);
    TEST_ASSERT(dec_rc == 0, "AEAD decryption must succeed");
    TEST_ASSERT_MEM_EQ(decrypted, plaintext, pt_len, "Decrypted text must match original plaintext");

    /* 3. Tampered Ciphertext detection */
    ciphertext[0] ^= 0x01;
    TEST_ASSERT(vpn_crypto_aead_decrypt(decrypted, ciphertext, pt_len, mac, ad, ad_len, counter, key) == -EBADMSG,
                "Tampered ciphertext must fail authentication with -EBADMSG");
    ciphertext[0] ^= 0x01; /* restore */

    /* 4. Tampered Auth Tag detection */
    mac[0] ^= 0xFF;
    TEST_ASSERT(vpn_crypto_aead_decrypt(decrypted, ciphertext, pt_len, mac, ad, ad_len, counter, key) == -EBADMSG,
                "Tampered auth tag must fail authentication with -EBADMSG");
    mac[0] ^= 0xFF; /* restore */

    /* 5. Wrong Key detection */
    uint8_t wrong_key[VPN_KEY_LEN];
    vpn_crypto_random_bytes(wrong_key, sizeof(wrong_key));
    TEST_ASSERT(vpn_crypto_aead_decrypt(decrypted, ciphertext, pt_len, mac, ad, ad_len, counter, wrong_key) == -EBADMSG,
                "Wrong key must fail authentication with -EBADMSG");

    /* 6. Desynchronized Nonce / Counter detection */
    TEST_ASSERT(vpn_crypto_aead_decrypt(decrypted, ciphertext, pt_len, mac, ad, ad_len, counter + 1, key) == -EBADMSG,
                "Mismatched counter must fail authentication with -EBADMSG");

    /* 7. Tampered Additional Data detection */
    const uint8_t wrong_ad[] = "Corrupted Header Data";
    TEST_ASSERT(vpn_crypto_aead_decrypt(decrypted, ciphertext, pt_len, mac, wrong_ad, sizeof(wrong_ad), counter, key) == -EBADMSG,
                "Tampered AD must fail authentication with -EBADMSG");
}

static void test_aead_zero_length_keepalive(void) {
    uint8_t key[VPN_KEY_LEN];
    vpn_crypto_random_bytes(key, sizeof(key));

    uint8_t mac[VPN_AUTH_TAG_LEN];
    uint64_t counter = 999;

    /* Encrypt zero-length payload */
    int enc_rc = vpn_crypto_aead_encrypt(NULL, mac, NULL, 0, NULL, 0, counter, key);
    TEST_ASSERT(enc_rc == 0, "Zero-length keepalive AEAD encrypt must succeed");

    /* Decrypt zero-length payload */
    int dec_rc = vpn_crypto_aead_decrypt(NULL, NULL, 0, mac, NULL, 0, counter, key);
    TEST_ASSERT(dec_rc == 0, "Zero-length keepalive AEAD decrypt must succeed");

    /* Corrupted tag on zero-length payload */
    mac[5] ^= 0x01;
    TEST_ASSERT(vpn_crypto_aead_decrypt(NULL, NULL, 0, mac, NULL, 0, counter, key) == -EBADMSG,
                "Corrupted tag on keepalive must fail with -EBADMSG");
}

static void test_x25519_diffie_hellman(void) {
    uint8_t alice_pub[VPN_PUBKEY_LEN], alice_priv[VPN_PRIVKEY_LEN];
    uint8_t bob_pub[VPN_PUBKEY_LEN], bob_priv[VPN_PRIVKEY_LEN];

    TEST_ASSERT(vpn_crypto_generate_keypair(alice_pub, alice_priv) == 0, "Alice keypair gen must succeed");
    TEST_ASSERT(vpn_crypto_generate_keypair(bob_pub, bob_priv) == 0, "Bob keypair gen must succeed");

    uint8_t shared_alice[VPN_KEY_LEN];
    uint8_t shared_bob[VPN_KEY_LEN];

    TEST_ASSERT(vpn_crypto_dh(shared_alice, bob_pub, alice_priv) == 0, "Alice DH must succeed");
    TEST_ASSERT(vpn_crypto_dh(shared_bob, alice_pub, bob_priv) == 0, "Bob DH must succeed");

    TEST_ASSERT_MEM_EQ(shared_alice, shared_bob, VPN_KEY_LEN, "Alice and Bob shared secrets must match");

    vpn_crypto_memzero(alice_priv, sizeof(alice_priv));
    vpn_crypto_memzero(bob_priv, sizeof(bob_priv));
    vpn_crypto_memzero(shared_alice, sizeof(shared_alice));
    vpn_crypto_memzero(shared_bob, sizeof(shared_bob));
}

int main(void) {
    printf("=== Phase 5: Crypto Abstraction & AEAD Tests ===\n");
    vpn_crypto_init();

    TEST_RUN(test_nonce_formatting);
    TEST_RUN(test_aead_encrypt_decrypt_roundtrip);
    TEST_RUN(test_aead_zero_length_keepalive);
    TEST_RUN(test_x25519_diffie_hellman);

    TEST_REPORT();
    return 0;
}
