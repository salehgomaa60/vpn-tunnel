#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  [FAIL] %s:%d: %s (%s)\n", __FILE__, __LINE__, msg, #cond); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp(a, b, len) != 0) { \
        printf("  [FAIL] %s:%d: %s (memory mismatch)\n", __FILE__, __LINE__, msg); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_RUN(test_fn) do { \
    g_tests_run++; \
    int prev_failed = g_tests_failed; \
    printf("[RUN]  %s\n", #test_fn); \
    test_fn(); \
    if (g_tests_failed == prev_failed) { \
        g_tests_passed++; \
        printf("  [PASS] %s\n", #test_fn); \
    } \
} while(0)

#define TEST_REPORT() do { \
    printf("\n========================================\n"); \
    printf("Test Results: %d run, %d passed, %d failed\n", \
           g_tests_run, g_tests_passed, g_tests_failed); \
    printf("========================================\n"); \
    if (g_tests_failed > 0) { \
        exit(1); \
    } \
} while(0)

#endif /* TEST_RUNNER_H */
