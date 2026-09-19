#include "test_runner.h"
#include "../src/tun.h"
#include "../src/config.h"
#include "../src/logging.h"
#include <errno.h>

static void test_tun_invalid_arguments(void) {
    tun_device_t tun;
    uint8_t buf[64];

    /* Test NULL tun pointer */
    TEST_ASSERT(tun_open(NULL, "vpn0", 1440) == -EINVAL, "NULL tun struct must return -EINVAL");

    /* Test invalid MTU limits */
    TEST_ASSERT(tun_open(&tun, "vpn0", 500) == -EINVAL, "MTU < 576 must return -EINVAL");
    TEST_ASSERT(tun_open(&tun, "vpn0", 5000) == -EINVAL, "MTU > 2048 must return -EINVAL");

    /* Test invalid read/write buffers */
    memset(&tun, 0, sizeof(tun));
    tun.fd = -1;
    tun.mtu = 1440;
    TEST_ASSERT(tun_read(&tun, NULL, sizeof(buf)) == -EINVAL, "NULL read buffer must return -EINVAL");
    TEST_ASSERT(tun_read(&tun, buf, 0) == -EINVAL, "Zero read len must return -EINVAL");
    TEST_ASSERT(tun_write(&tun, NULL, sizeof(buf)) == -EINVAL, "NULL write buffer must return -EINVAL");
    TEST_ASSERT(tun_write(&tun, buf, 0) == -EINVAL, "Zero write len must return -EINVAL");

    /* Test MTU boundary check on write */
    tun.fd = 999; /* simulated open fd */
    TEST_ASSERT(tun_write(&tun, buf, 1500) == -EMSGSIZE, "Write > MTU must return -EMSGSIZE");
}

static void test_tun_lifecycle(void) {
    tun_device_t tun;
    log_set_level(LOG_LEVEL_DEBUG);

    int rc = tun_open(&tun, "testtun%d", VPN_DEFAULT_INNER_MTU);
    if (rc == 0) {
        printf("  [INFO] Successfully created TUN interface '%s'\n", tun.name);
        TEST_ASSERT(tun.fd >= 0, "Valid TUN fd expected");
        TEST_ASSERT(tun.mtu == VPN_DEFAULT_INNER_MTU, "MTU should match configured value");

        /* Configure IP and netmask */
        int ip_rc = tun_set_ip(&tun, "10.42.0.1", "255.255.255.0");
        TEST_ASSERT(ip_rc == 0, "tun_set_ip should succeed");

        /* Bring interface up */
        int up_rc = tun_set_up(&tun);
        TEST_ASSERT(up_rc == 0, "tun_set_up should succeed");

        /* Close interface */
        tun_close(&tun);
        TEST_ASSERT(tun.fd == -1, "tun_close should invalidate fd to -1");
    } else {
        printf("  [INFO] tun_open returned %d (%s) - running in unprivileged container/sandbox\n",
               rc, strerror(-rc));
        TEST_ASSERT(rc == -EPERM || rc == -ENOENT || rc == -EACCES || rc == -ENOSYS,
                    "Failure should be permission or device availability related");
    }
}

int main(void) {
    printf("=== Phase 2: Linux TUN Interface Tests ===\n");

    TEST_RUN(test_tun_invalid_arguments);
    TEST_RUN(test_tun_lifecycle);

    TEST_REPORT();
    return 0;
}
