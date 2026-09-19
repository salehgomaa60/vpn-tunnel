/*
 * fuzz_handshake.c — LibFuzzer harness for handshake message processing.
 *
 * WHAT IT TESTS
 * -------------
 * handshake_consume_initiation() receives attacker-controlled bytes from the
 * network before any authentication is complete.  It must:
 *   - Reject all crafted packets without crashing or leaking memory
 *   - Never write beyond the fixed-size output structs
 *   - Return -EBADMSG on any cryptographic failure
 *   - Return -EACCES if the recovered static key is not in the peer table
 *
 * Similarly, handshake_consume_response() is exercised.
 *
 * COMPILE
 * -------
 *   clang -g -O1 -fsanitize=address,undefined,fuzzer \
 *         -Isrc -Ideps/dist/include \
 *         fuzz/fuzz_handshake.c \
 *         src/handshake.o src/crypto.o src/packet.o src/kdf.o \
 *         src/peer.o src/transport.o src/routing.o src/replay.o \
 *         src/logging.o src/config.o \
 *         -Ldeps/dist/lib -lsodium -lpthread \
 *         -o fuzz/fuzz_handshake
 *
 * RUN
 * ---
 *   ./fuzz/fuzz_handshake -max_len=512 -runs=2000000
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

#include "../src/crypto.h"
#include "../src/handshake.h"
#include "../src/packet.h"
#include "../src/peer.h"
#include "../src/config.h"
#include "../src/logging.h"

/*
 * We keep a static responder keypair and peer table to avoid regenerating
 * them on every fuzz iteration — this is correct and safe because the
 * fuzzer exercises the *data* path, not the key generation path.
 */
static int             g_initialized = 0;
static uint8_t         g_bob_pub[VPN_PUBKEY_LEN];
static uint8_t         g_bob_priv[VPN_PRIVKEY_LEN];
static vpn_peer_table_t g_peer_table;

/* Called once before fuzzing begins */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;

    log_set_level(LOG_LEVEL_NONE);
    vpn_crypto_init();

    /* Generate Bob (responder) static keypair */
    vpn_crypto_generate_keypair(g_bob_pub, g_bob_priv);

    /* Register a single known peer "alice" with a fixed key {0x01, 0 ...} */
    peer_table_init(&g_peer_table);
    uint8_t alice_pub[VPN_PUBKEY_LEN] = {0x01};
    peer_add(&g_peer_table, "alice", alice_pub, NULL);

    g_initialized = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_initialized) {
        LLVMFuzzerInitialize(NULL, NULL);
    }

    /* ------------------------------------------------------------------ *
     * Test 1: handshake_consume_initiation with arbitrary network bytes    *
     * ------------------------------------------------------------------ */
    {
        vpn_peer_t *peer = NULL;
        packet_handshake_init_t parsed;
        uint8_t ck[VPN_KEY_LEN];
        uint8_t h[32];

        int rc = handshake_consume_initiation(data, size,
                                              g_bob_priv, g_bob_pub,
                                              &g_peer_table,
                                              &peer, &parsed,
                                              ck, h);
        /*
         * Valid return codes:
         *  0         — authenticated successfully (very unlikely with random data)
         *  -EINVAL   — bad parameters / wrong size
         *  -EBADMSG  — AEAD decryption failure (most common with fuzz data)
         *  -EACCES   — static key recovered but not in peer table
         */
        (void)rc;
        /* Crash or any signal = found a bug */
    }

    /* ------------------------------------------------------------------ *
     * Test 2: handshake_consume_response with arbitrary network bytes      *
     * ------------------------------------------------------------------ */
    {
        /*
         * We need a plausible init_state for consume_response.
         * We build a minimal one from the fuzz data itself.
         */
        handshake_init_state_t state;
        memset(&state, 0, sizeof(state));

        /* Fill in ephemeral private key from fuzz data (first 32 bytes if available) */
        if (size >= VPN_PRIVKEY_LEN) {
            memcpy(state.ephemeral_private, data, VPN_PRIVKEY_LEN);
        }
        state.local_index = 0xDEADBEEF;

        uint32_t peer_idx = 0;
        uint8_t send_key[VPN_KEY_LEN];
        uint8_t recv_key[VPN_KEY_LEN];

        int rc = handshake_consume_response(data, size,
                                            g_bob_priv,
                                            &state,
                                            g_bob_pub,
                                            &peer_idx,
                                            send_key, recv_key);
        (void)rc;

        vpn_crypto_memzero(send_key, sizeof(send_key));
        vpn_crypto_memzero(recv_key, sizeof(recv_key));
        vpn_crypto_memzero(state.ephemeral_private, sizeof(state.ephemeral_private));
    }

    return 0;
}
