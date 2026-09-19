/*
 * fuzz_packet_parser.c — LibFuzzer harness for packet parsing.
 *
 * WHAT IT TESTS
 * -------------
 * All three packet parse functions are exercised with fully attacker-controlled
 * byte sequences.  A well-behaved parser must:
 *   - Never crash or abort
 *   - Never read out of the provided buffer bounds
 *   - Return a defined error code for every malformed input
 *   - Never write more data than the fixed-size output struct
 *
 * COMPILE (Linux, clang with ASan + UBSan + LibFuzzer)
 * ----------------------------------------------------
 *   clang -g -O1 -fsanitize=address,undefined,fuzzer \
 *         -Isrc -Ideps/dist/include \
 *         fuzz/fuzz_packet_parser.c \
 *         src/packet.o src/logging.o src/config.o \
 *         -Ldeps/dist/lib -lsodium -lpthread \
 *         -o fuzz/fuzz_packet_parser
 *
 * RUN
 * ---
 *   ./fuzz/fuzz_packet_parser -max_len=2048 -runs=1000000
 *   ./fuzz/fuzz_packet_parser corpus/   # with a seed corpus directory
 *
 * SEED CORPUS
 * -----------
 * Place real, valid wire-format packets captured during unit test runs into
 * fuzz/corpus/ to bootstrap coverage faster.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../src/packet.h"
#include "../src/config.h"
#include "../src/logging.h"

/* LibFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Silence all log output during fuzzing to avoid I/O overhead */
    log_set_level(LOG_LEVEL_NONE);

    /* ------------------------------------------------------------------ *
     * 1. Handshake Initiation Parser                                       *
     * ------------------------------------------------------------------ */
    {
        packet_handshake_init_t out;
        /* Intentionally do NOT check return code — we are looking for crashes */
        (void)packet_parse_handshake_init(data, size, &out);
    }

    /* ------------------------------------------------------------------ *
     * 2. Handshake Response Parser                                         *
     * ------------------------------------------------------------------ */
    {
        packet_handshake_resp_t out;
        (void)packet_parse_handshake_resp(data, size, &out);
    }

    /* ------------------------------------------------------------------ *
     * 3. Data / Keepalive Packet Parser                                    *
     * ------------------------------------------------------------------ */
    {
        packet_data_t out;
        (void)packet_parse_data(data, size, &out);
    }

    /* ------------------------------------------------------------------ *
     * 4. Packet Type Peek (single-byte read with length guard)             *
     * ------------------------------------------------------------------ */
    {
        (void)packet_peek_type(data, size);
    }

    return 0; /* Non-zero return would tell LibFuzzer to discard input */
}
