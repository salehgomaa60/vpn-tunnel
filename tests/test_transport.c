#include "test_runner.h"
#include "../src/transport.h"
#include "../src/config.h"
#include "../src/logging.h"
#include <unistd.h>
#include <errno.h>

static void test_endpoint_parsing_and_formatting(void) {
    vpn_endpoint_t ep;
    char str_buf[128];

    /* Test valid IPv4 */
    TEST_ASSERT(endpoint_parse("192.168.1.100:51820", &ep) == 0, "Valid IPv4 parse should succeed");
    TEST_ASSERT(endpoint_to_string(&ep, str_buf, sizeof(str_buf)) == 0, "Formatting IPv4 should succeed");
    TEST_ASSERT(strcmp(str_buf, "192.168.1.100:51820") == 0, "Formatted string must match input");

    /* Test valid IPv6 */
    TEST_ASSERT(endpoint_parse("[::1]:8080", &ep) == 0, "Valid IPv6 parse should succeed");
    TEST_ASSERT(endpoint_to_string(&ep, str_buf, sizeof(str_buf)) == 0, "Formatting IPv6 should succeed");
    TEST_ASSERT(strcmp(str_buf, "[::1]:8080") == 0, "Formatted IPv6 must match input");

    /* Test invalid inputs */
    TEST_ASSERT(endpoint_parse(NULL, &ep) == -EINVAL, "NULL string should return -EINVAL");
    TEST_ASSERT(endpoint_parse("192.168.1.1", &ep) == -EINVAL, "Missing port should return -EINVAL");
    TEST_ASSERT(endpoint_parse("192.168.1.1:0", &ep) == -EINVAL, "Port 0 should return -EINVAL");
    TEST_ASSERT(endpoint_parse("192.168.1.1:70000", &ep) == -EINVAL, "Port > 65535 should return -EINVAL");
    TEST_ASSERT(endpoint_parse("invalid_ip:51820", &ep) == -EINVAL, "Invalid IP string should fail");
}

static void test_endpoint_equality(void) {
    vpn_endpoint_t ep1, ep2, ep3;

    endpoint_parse("10.0.0.1:51820", &ep1);
    endpoint_parse("10.0.0.1:51820", &ep2);
    endpoint_parse("10.0.0.1:51821", &ep3);

    TEST_ASSERT(endpoint_equal(&ep1, &ep2) == 1, "Identical endpoints must be equal");
    TEST_ASSERT(endpoint_equal(&ep1, &ep3) == 0, "Endpoints with different ports must not be equal");
    TEST_ASSERT(endpoint_equal(&ep1, NULL) == 0, "Comparison with NULL must return 0");
}

static void test_udp_loopback_transmission(void) {
    /* Bind two sockets on localhost with ephemeral ports (port 0) */
    int fd_server = transport_open("127.0.0.1", 0);
    TEST_ASSERT(fd_server >= 0, "Server socket creation must succeed");

    int fd_client = transport_open("127.0.0.1", 0);
    TEST_ASSERT(fd_client >= 0, "Client socket creation must succeed");

    /* Obtain assigned port for server */
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);
    getsockname(fd_server, (struct sockaddr *)&sin, &sin_len);
    uint16_t server_port = ntohs(sin.sin_port);

    char server_ep_str[64];
    snprintf(server_ep_str, sizeof(server_ep_str), "127.0.0.1:%u", server_port);

    vpn_endpoint_t server_ep;
    TEST_ASSERT(endpoint_parse(server_ep_str, &server_ep) == 0, "Server endpoint parse must succeed");

    /* Send packet from client to server */
    const uint8_t test_msg[] = "Hello Secure VPN Tunnel";
    size_t msg_len = sizeof(test_msg);

    ssize_t sent = transport_send(fd_client, &server_ep, test_msg, msg_len);
    TEST_ASSERT(sent == (ssize_t)msg_len, "All bytes must be sent");

    /* Test oversized packet rejection */
    uint8_t oversized[VPN_MAX_PACKET_SIZE + 100];
    TEST_ASSERT(transport_send(fd_client, &server_ep, oversized, sizeof(oversized)) == -EMSGSIZE,
                "Oversized datagram must return -EMSGSIZE");

    /* Receive packet on server */
    uint8_t recv_buf[512];
    vpn_endpoint_t src_ep;
    ssize_t n = 0;
    int attempts = 0;

    while (n == 0 && attempts < 100) {
        n = transport_recv(fd_server, &src_ep, recv_buf, sizeof(recv_buf));
        attempts++;
        if (n == 0) usleep(1000); /* 1ms backoff */
    }

    TEST_ASSERT(n == (ssize_t)msg_len, "Received bytes must match sent bytes");
    TEST_ASSERT_MEM_EQ(recv_buf, test_msg, msg_len, "Received content must match transmitted data");

    /* Close sockets */
    transport_close(&fd_server);
    transport_close(&fd_client);
    TEST_ASSERT(fd_server == -1, "Closed fd must be set to -1");
    TEST_ASSERT(fd_client == -1, "Closed fd must be set to -1");
}

int main(void) {
    printf("=== Phase 3: UDP Transport & Endpoint Tests ===\n");

    TEST_RUN(test_endpoint_parsing_and_formatting);
    TEST_RUN(test_endpoint_equality);
    TEST_RUN(test_udp_loopback_transmission);

    TEST_REPORT();
    return 0;
}
