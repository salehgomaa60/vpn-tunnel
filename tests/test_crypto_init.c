#include "test_runner.h"
#include <sodium.h>
#include "../src/config.h"
#include "../src/logging.h"

static void test_sodium_initialization(void) {
    /* sodium_init() returns 0 on success, 1 if already initialized, -1 on failure */
    int rc = sodium_init();
    TEST_ASSERT(rc >= 0, "sodium_init must succeed");
}

static void test_sodium_memzero_and_compare(void) {
    uint8_t secret[VPN_KEY_LEN];
    uint8_t zero_buf[VPN_KEY_LEN] = {0};

    /* Generate random bytes */
    randombytes_buf(secret, sizeof(secret));

    /* Ensure random bytes are non-zero with high probability */
    TEST_ASSERT(sodium_memcmp(secret, zero_buf, sizeof(secret)) != 0,
                "Random bytes must not be all zeros");

    /* Securely wipe the secret */
    sodium_memzero(secret, sizeof(secret));

    /* Verify memory is wiped to zero in constant-time */
    TEST_ASSERT(sodium_memcmp(secret, zero_buf, sizeof(secret)) == 0,
                "sodium_memzero must clear buffer to zero");
}

static void test_sodium_constant_time_comparison(void) {
    uint8_t buf1[32] = {0x42};
    uint8_t buf2[32] = {0x42};
    uint8_t buf3[32] = {0x43};

    TEST_ASSERT(sodium_memcmp(buf1, buf2, 32) == 0, "Identical buffers must match");
    TEST_ASSERT(sodium_memcmp(buf1, buf3, 32) != 0, "Different buffers must not match");
}

static void test_logging_framework(void) {
    log_set_level(LOG_LEVEL_DEBUG);
    TEST_ASSERT(log_get_level() == LOG_LEVEL_DEBUG, "Log level should be DEBUG");

    LOG_DEBUG("Testing debug log %d", 123);
    LOG_INFO("Testing info log %s", "hello");
    LOG_WARN("Testing warn log");
    LOG_ERROR("Testing error log");

    log_set_level(LOG_LEVEL_INFO);
    TEST_ASSERT(log_get_level() == LOG_LEVEL_INFO, "Log level should be INFO");
}

int main(void) {
    printf("=== Phase 1: libsodium & Infrastructure Tests ===\n");

    TEST_RUN(test_sodium_initialization);
    TEST_RUN(test_sodium_memzero_and_compare);
    TEST_RUN(test_sodium_constant_time_comparison);
    TEST_RUN(test_logging_framework);

    TEST_REPORT();
    return 0;
}
