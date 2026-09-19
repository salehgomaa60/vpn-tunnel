/*
 * fuzz_replay.c — LibFuzzer harness for the replay protection filter.
 *
 * WHAT IT TESTS
 * -------------
 * The replay filter is exercised with arbitrary sequences of 64-bit counters.
 * It must:
 *   - Never crash, regardless of counter value (including UINT64_MAX)
 *   - Correctly maintain the bitmap invariant: once a counter is marked seen,
 *     replay_check must return 0 for that counter every subsequent call
 *   - Accept future counters (advance the window)
 *   - Reject stale counters that fall outside the 2048-packet window
 *
 * The harness also verifies the fundamental security invariant inline:
 * a counter returned as "valid" by replay_check must be rejected after
 * replay_update is called for it.
 *
 * COMPILE
 * -------
 *   clang -g -O1 -fsanitize=address,undefined,fuzzer \
 *         -Isrc \
 *         fuzz/fuzz_replay.c \
 *         src/replay.o src/logging.o \
 *         -Ldeps/dist/lib -lsodium -lpthread \
 *         -o fuzz/fuzz_replay
 *
 * RUN
 * ---
 *   ./fuzz/fuzz_replay -max_len=8192 -runs=5000000
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../src/replay.h"
#include "../src/logging.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    log_set_level(LOG_LEVEL_NONE);

    replay_filter_t filter;
    replay_init(&filter);

    /*
     * Interpret input as a stream of 8-byte little-endian uint64 values.
     * Each value becomes a counter to feed through the filter.
     */
    const uint8_t *p   = data;
    size_t         rem = size;

    while (rem >= 8) {
        uint64_t counter =
            ((uint64_t)p[0])        |
            ((uint64_t)p[1] << 8)   |
            ((uint64_t)p[2] << 16)  |
            ((uint64_t)p[3] << 24)  |
            ((uint64_t)p[4] << 32)  |
            ((uint64_t)p[5] << 40)  |
            ((uint64_t)p[6] << 48)  |
            ((uint64_t)p[7] << 56);

        p   += 8;
        rem -= 8;

        int is_valid = replay_check(&filter, counter);

        if (is_valid) {
            /* Mark it seen */
            replay_update(&filter, counter);

            /*
             * SECURITY INVARIANT: After update, the same counter must
             * ALWAYS be rejected.  If this fails it is a critical bug.
             */
            int after = replay_check(&filter, counter);
            if (after != 0) {
                /* replay_check returned 1 for an already-seen counter — BUG */
                __builtin_trap();
            }
        }
    }

    return 0;
}
