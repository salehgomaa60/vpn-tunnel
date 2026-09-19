/*
 * gen_corpus.c — Seed corpus generator for LibFuzzer harnesses.
 *
 * Generates a small set of valid wire-format packets from an actual handshake
 * to give the fuzzer good starting coverage before it begins blind mutation.
 *
 * COMPILE & RUN (on Linux target)
 * --------------------------------
 *   gcc -Wall -Isrc -Ideps/dist/include \
 *       fuzz/gen_corpus.c src/*.o \
 *       -Ldeps/dist/lib -lsodium -lpthread \
 *       -o fuzz/gen_corpus
 *
 *   mkdir -p fuzz/corpus
 *   ./fuzz/gen_corpus fuzz/corpus/
 *
 * OUTPUT FILES (written into the given directory)
 * ------------------------------------------------
 *   handshake_init.bin     — valid 148-byte Handshake Initiation
 *   handshake_resp.bin     — valid 92-byte Handshake Response
 *   data_small.bin         — valid 32+N data packet with 64-byte payload
 *   data_keepalive.bin     — valid 32-byte keepalive packet
 *   data_zeros.bin         — all-zero ciphertext block (boundary input)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto.h"
#include "../src/packet.h"
#include "../src/handshake.h"
#include "../src/peer.h"
#include "../src/config.h"
#include "../src/logging.h"

static void write_file(const char *dir, const char *name,
                       const uint8_t *data, size_t len) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Cannot open %s for writing\n", path);
        return;
    }
    fwrite(data, 1, len, f);
    fclose(f);
    printf("  Wrote %zu bytes -> %s\n", len, path);
}

int main(int argc, char **argv) {
    const char *out_dir = argc > 1 ? argv[1] : "fuzz/corpus";

    log_set_level(LOG_LEVEL_NONE);

    if (vpn_crypto_init() < 0) {
        fprintf(stderr, "vpn_crypto_init failed\n");
        return 1;
    }

    printf("Generating seed corpus in: %s/\n", out_dir);

    /* ------------------------------------------------------------------ *
     * 1. Generate a valid handshake exchange                               *
     * ------------------------------------------------------------------ */
    uint8_t alice_pub[VPN_PUBKEY_LEN], alice_priv[VPN_PRIVKEY_LEN];
    uint8_t bob_pub[VPN_PUBKEY_LEN],   bob_priv[VPN_PRIVKEY_LEN];
    vpn_crypto_generate_keypair(alice_pub, alice_priv);
    vpn_crypto_generate_keypair(bob_pub, bob_priv);

    vpn_peer_table_t bob_table;
    peer_table_init(&bob_table);
    peer_add(&bob_table, "alice", alice_pub, NULL);

    /* Handshake Initiation */
    uint8_t init_pkt[PACKET_HANDSHAKE_INIT_LEN];
    handshake_init_state_t alice_state;
    int init_len = handshake_create_initiation(init_pkt, sizeof(init_pkt),
                                               alice_priv, alice_pub, bob_pub,
                                               0x12345678, &alice_state);
    if (init_len == PACKET_HANDSHAKE_INIT_LEN) {
        write_file(out_dir, "handshake_init.bin", init_pkt, (size_t)init_len);
    }

    /* Handshake Response */
    vpn_peer_t   *auth_peer = NULL;
    packet_handshake_init_t parsed_init;
    uint8_t ck[VPN_KEY_LEN], h[32];
    uint8_t resp_pkt[PACKET_HANDSHAKE_RESP_LEN];
    uint8_t bob_send[VPN_KEY_LEN], bob_recv[VPN_KEY_LEN];

    if (handshake_consume_initiation(init_pkt, sizeof(init_pkt),
                                     bob_priv, bob_pub, &bob_table,
                                     &auth_peer, &parsed_init, ck, h) == 0 && auth_peer) {
        int resp_len = handshake_create_response(resp_pkt, sizeof(resp_pkt),
                                                  bob_priv,
                                                  parsed_init.unencrypted_ephemeral,
                                                  auth_peer->public_key,
                                                  0xABCDEF01,
                                                  parsed_init.sender_index,
                                                  ck, h,
                                                  bob_send, bob_recv);
        if (resp_len == PACKET_HANDSHAKE_RESP_LEN) {
            write_file(out_dir, "handshake_resp.bin", resp_pkt, (size_t)resp_len);
        }
    }

    /* ------------------------------------------------------------------ *
     * 2. Generate valid data packets                                       *
     * ------------------------------------------------------------------ */
    uint8_t key[VPN_KEY_LEN];
    vpn_crypto_random_bytes(key, sizeof(key));

    /* Small data packet: 64-byte payload */
    {
        uint8_t payload[64];
        vpn_crypto_random_bytes(payload, sizeof(payload));

        uint8_t ciphertext[64];
        uint8_t tag[VPN_AUTH_TAG_LEN];
        vpn_crypto_aead_encrypt(ciphertext, tag, payload, sizeof(payload),
                                NULL, 0, 0, key);

        uint8_t wire[PACKET_DATA_MIN_LEN + 64];
        int wlen = packet_serialize_data(wire, sizeof(wire),
                                         0x00001234, 0ULL,
                                         ciphertext, sizeof(ciphertext), tag);
        if (wlen > 0) {
            write_file(out_dir, "data_small.bin", wire, (size_t)wlen);
        }
    }

    /* Keepalive (0-byte payload) */
    {
        uint8_t tag[VPN_AUTH_TAG_LEN];
        vpn_crypto_aead_encrypt(NULL, tag, NULL, 0, NULL, 0, 1, key);

        uint8_t wire[PACKET_DATA_MIN_LEN];
        int wlen = packet_serialize_data(wire, sizeof(wire),
                                         0x00001234, 1ULL,
                                         NULL, 0, tag);
        if (wlen > 0) {
            write_file(out_dir, "data_keepalive.bin", wire, (size_t)wlen);
        }
    }

    /* All-zero ciphertext block (boundary / edge case) */
    {
        uint8_t wire[PACKET_DATA_MIN_LEN + 16] = {0};
        wire[0] = PACKET_TYPE_DATA; /* set valid type byte */
        write_file(out_dir, "data_zeros.bin", wire, sizeof(wire));
    }

    /* Clean up */
    peer_table_destroy(&bob_table);
    vpn_crypto_memzero(alice_priv, sizeof(alice_priv));
    vpn_crypto_memzero(bob_priv,   sizeof(bob_priv));
    vpn_crypto_memzero(bob_send,   sizeof(bob_send));
    vpn_crypto_memzero(bob_recv,   sizeof(bob_recv));
    vpn_crypto_memzero(key,        sizeof(key));

    printf("Seed corpus generation complete.\n");
    return 0;
}
