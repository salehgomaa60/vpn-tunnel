#include "test_runner.h"
#include "../src/replay.h"
#include "../src/logging.h"

static void test_sequential_packets(void) {
    replay_filter_t filter;
    replay_init(&filter);

    for (uint64_t i = 0; i < 50; i++) {
        TEST_ASSERT(replay_check(&filter, i) == 1, "Sequential packet must be accepted");
        replay_update(&filter, i);
        TEST_ASSERT(replay_check(&filter, i) == 0, "Duplicate sequential packet must be rejected");
    }
}

static void test_out_of_order_packets(void) {
    replay_filter_t filter;
    replay_init(&filter);

    /* Receive packet 10 */
    TEST_ASSERT(replay_check(&filter, 10) == 1, "Packet 10 must be accepted");
    replay_update(&filter, 10);

    /* Receive packet 5 (arrived out of order) */
    TEST_ASSERT(replay_check(&filter, 5) == 1, "Out-of-order packet 5 must be accepted");
    replay_update(&filter, 5);

    /* Replay of packet 5 */
    TEST_ASSERT(replay_check(&filter, 5) == 0, "Replayed packet 5 must be rejected");

    /* Replay of packet 10 */
    TEST_ASSERT(replay_check(&filter, 10) == 0, "Replayed packet 10 must be rejected");

    /* Receive packet 7 */
    TEST_ASSERT(replay_check(&filter, 7) == 1, "Out-of-order packet 7 must be accepted");
    replay_update(&filter, 7);
    TEST_ASSERT(replay_check(&filter, 7) == 0, "Replayed packet 7 must be rejected");

    /* Advance to packet 15 */
    TEST_ASSERT(replay_check(&filter, 15) == 1, "Packet 15 must be accepted");
    replay_update(&filter, 15);

    /* Packet 10 is still recorded */
    TEST_ASSERT(replay_check(&filter, 10) == 0, "Packet 10 must still be recorded as seen");
}

static void test_sliding_window_boundaries(void) {
    replay_filter_t filter;
    replay_init(&filter);

    /* Advance window to counter 3000 */
    replay_update(&filter, 3000);
    TEST_ASSERT(filter.last_counter == 3000, "Last counter must be 3000");

    /* Counter 0 is diff=3000 > 2048 (outside window) -> Reject */
    TEST_ASSERT(replay_check(&filter, 0) == 0, "Stale counter 0 must be rejected");

    /* Counter 952 is diff=2048 >= 2048 -> Reject */
    TEST_ASSERT(replay_check(&filter, 3000 - VPN_REPLAY_WINDOW_SIZE) == 0,
                "Counter exactly at or beyond window size must be rejected");

    /* Counter 953 is diff=2047 < 2048 -> Accept */
    uint64_t boundary_counter = 3000 - (VPN_REPLAY_WINDOW_SIZE - 1);
    TEST_ASSERT(replay_check(&filter, boundary_counter) == 1,
                "Counter on the valid edge of window must be accepted");
    replay_update(&filter, boundary_counter);
    TEST_ASSERT(replay_check(&filter, boundary_counter) == 0,
                "Replay of boundary counter must be rejected");
}

static void test_large_counter_jump(void) {
    replay_filter_t filter;
    replay_init(&filter);

    replay_update(&filter, 100);

    /* Jump ahead by 1,000,000 */
    uint64_t huge_counter = 1000100;
    TEST_ASSERT(replay_check(&filter, huge_counter) == 1, "Large forward jump must be accepted");
    replay_update(&filter, huge_counter);

    /* Old counter 100 is now completely obsolete */
    TEST_ASSERT(replay_check(&filter, 100) == 0, "Obsolete counter 100 must be rejected");
    /* Huge counter cannot be replayed */
    TEST_ASSERT(replay_check(&filter, huge_counter) == 0, "Huge counter replay must be rejected");
}

int main(void) {
    printf("=== Phase 8: Replay Protection Tests ===\n");

    TEST_RUN(test_sequential_packets);
    TEST_RUN(test_out_of_order_packets);
    TEST_RUN(test_sliding_window_boundaries);
    TEST_RUN(test_large_counter_jump);

    TEST_REPORT();
    return 0;
}
