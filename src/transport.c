/*
 * transport.c — UDP Transport and Endpoint Management
 *
 * ASYNCHRONOUS UDP TRANSPORT & NAT ROAMING
 * ----------------------------------------
 * In a VPN, all encrypted tunnel packets travel across the public Internet
 * inside UDP datagrams.  This module manages:
 *   1. Network Endpoints: parsing, formatting, and comparing IP:Port addresses.
 *   2. Non-blocking Sockets: creating and configuring UDP sockets for event loops.
 *   3. Network I/O: sending datagrams (sendto) and receiving datagrams (recvfrom).
 *
 * UNTRUSTED INPUT & SECURITY BOUNDARIES
 * -------------------------------------
 *  - Every byte received via `transport_recv()` comes from the untrusted network.
 *  - The source endpoint (`src`) recorded by `recvfrom()` is controlled by the outer
 *    IP routing headers. An attacker can forge source IP addresses on UDP datagrams.
 *  - Therefore, `src` is used for endpoint roaming ONLY AFTER the inner payload passes
 *    crypto authentication (AEAD decryption or MAC verification).
 */

#include "transport.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* =========================================================================
 * endpoint_parse
 *
 * Parse an IP:port string into a `vpn_endpoint_t` structure.
 * Supports both IPv4 ("192.168.1.1:51820") and IPv6 ("[2001:db8::1]:51820").
 *
 * INPUT:
 *   str      : NUL-terminated string, e.g. "1.2.3.4:51820" or "[::1]:51820".
 *   endpoint : pointer to caller-allocated structure to populate.
 *
 * OUTPUT:
 *   endpoint->addr     : populated `struct sockaddr_storage` (in network byte order).
 *   endpoint->addr_len : sizeof(sockaddr_in) or sizeof(sockaddr_in6).
 *
 * RETURN:
 *   0 on success, -EINVAL on invalid format or invalid IP address.
 * ========================================================================= */
int endpoint_parse(const char *str, vpn_endpoint_t *endpoint) {
    if (!str || !endpoint) {
        return -EINVAL;
    }

    memset(endpoint, 0, sizeof(*endpoint));

    /* ---------------------------------------------------------------------
     * IPv6 Parsing: Format "[2001:db8::1]:51820"
     * --------------------------------------------------------------------- */
    if (str[0] == '[') {
        const char *closing = strchr(str, ']');
        if (!closing || *(closing + 1) != ':') {
            return -EINVAL;
        }

        char ip_buf[INET6_ADDRSTRLEN] = {0};
        size_t ip_len = closing - (str + 1);
        if (ip_len >= sizeof(ip_buf)) {
            return -EINVAL;
        }
        memcpy(ip_buf, str + 1, ip_len);

        int port = atoi(closing + 2);
        if (port <= 0 || port > 65535) {
            return -EINVAL;
        }

        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&endpoint->addr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons((uint16_t)port); /* Network byte order (big-endian) */
        if (inet_pton(AF_INET6, ip_buf, &sa6->sin6_addr) <= 0) {
            return -EINVAL;
        }
        endpoint->addr_len = sizeof(struct sockaddr_in6);
        return 0;
    }

    /* ---------------------------------------------------------------------
     * IPv4 Parsing: Format "192.168.1.1:51820"
     * --------------------------------------------------------------------- */
    const char *colon = strrchr(str, ':');
    if (!colon) {
        return -EINVAL;
    }

    char ip_buf[INET_ADDRSTRLEN] = {0};
    size_t ip_len = colon - str;
    if (ip_len == 0 || ip_len >= sizeof(ip_buf)) {
        return -EINVAL;
    }
    memcpy(ip_buf, str, ip_len);

    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) {
        return -EINVAL;
    }

    struct sockaddr_in *sa4 = (struct sockaddr_in *)&endpoint->addr;
    sa4->sin_family = AF_INET;
    sa4->sin_port = htons((uint16_t)port); /* Network byte order (big-endian) */
    if (inet_pton(AF_INET, ip_buf, &sa4->sin_addr) <= 0) {
        return -EINVAL;
    }
    endpoint->addr_len = sizeof(struct sockaddr_in);
    return 0;
}

/* =========================================================================
 * endpoint_to_string
 *
 * Convert a `vpn_endpoint_t` structure back into a human-readable IP:port string.
 *
 * INPUT:
 *   endpoint : populated endpoint structure.
 *   buf      : destination string buffer.
 *   buf_len  : capacity of destination buffer.
 *
 * RETURN:
 *   0 on success, negative error code (-EINVAL, -ENOSPC, -EAFNOSUPPORT) on failure.
 * ========================================================================= */
int endpoint_to_string(const vpn_endpoint_t *endpoint, char *buf, size_t buf_len) {
    if (!endpoint || !buf || buf_len == 0) {
        return -EINVAL;
    }

    if (endpoint->addr.ss_family == AF_INET) {
        const struct sockaddr_in *sa4 = (const struct sockaddr_in *)&endpoint->addr;
        char ip_buf[INET_ADDRSTRLEN] = {0};
        if (!inet_ntop(AF_INET, &sa4->sin_addr, ip_buf, sizeof(ip_buf))) {
            return -errno;
        }
        int written = snprintf(buf, buf_len, "%s:%u", ip_buf, ntohs(sa4->sin_port));
        if (written < 0 || (size_t)written >= buf_len) {
            return -ENOSPC;
        }
        return 0;
    } else if (endpoint->addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)&endpoint->addr;
        char ip_buf[INET6_ADDRSTRLEN] = {0};
        if (!inet_ntop(AF_INET6, &sa6->sin6_addr, ip_buf, sizeof(ip_buf))) {
            return -errno;
        }
        int written = snprintf(buf, buf_len, "[%s]:%u", ip_buf, ntohs(sa6->sin6_port));
        if (written < 0 || (size_t)written >= buf_len) {
            return -ENOSPC;
        }
        return 0;
    }

    return -EAFNOSUPPORT;
}

/* =========================================================================
 * endpoint_equal
 *
 * Compare two endpoints for equality (address family, IP address, and port).
 *
 * RETURN:
 *   1 if identical, 0 if different or invalid arguments.
 * ========================================================================= */
int endpoint_equal(const vpn_endpoint_t *a, const vpn_endpoint_t *b) {
    if (!a || !b || a->addr.ss_family != b->addr.ss_family) {
        return 0;
    }

    if (a->addr.ss_family == AF_INET) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)&a->addr;
        const struct sockaddr_in *sb = (const struct sockaddr_in *)&b->addr;
        return (sa->sin_port == sb->sin_port) &&
               (sa->sin_addr.s_addr == sb->sin_addr.s_addr);
    } else if (a->addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)&a->addr;
        const struct sockaddr_in6 *sb = (const struct sockaddr_in6 *)&b->addr;
        return (sa->sin6_port == sb->sin6_port) &&
               (memcmp(&sa->sin6_addr, &sb->sin6_addr, sizeof(struct in6_addr)) == 0);
    }

    return 0;
}

/* =========================================================================
 * transport_open
 *
 * Create, configure, and bind a non-blocking UDP socket.
 *
 * PARAMETERS:
 *   bind_ip : IP address string to bind to (e.g. "0.0.0.0" or "::"), or NULL.
 *   port    : UDP port to bind to (e.g. 51820, or 0 for dynamic kernel-assigned port).
 *
 * DETAILS:
 *   - Creates socket with SOCK_DGRAM.
 *   - Sets O_NONBLOCK so recvfrom/sendto never block the main loop thread.
 *   - Sets SO_REUSEADDR so daemon restarts can rebind immediately.
 *   - Sets FD_CLOEXEC so socket descriptor isn't leaked to child processes.
 *
 * RETURN:
 *   Socket file descriptor (>= 0) on success, or negative errno on failure.
 * ========================================================================= */
int transport_open(const char *bind_ip, uint16_t port) {
    int domain = AF_INET;
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    memset(&addr, 0, sizeof(addr));

    if (bind_ip && strchr(bind_ip, ':')) {
        domain = AF_INET6;
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&addr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        if (bind_ip[0] != '\0' && strcmp(bind_ip, "::") != 0) {
            if (inet_pton(AF_INET6, bind_ip, &sa6->sin6_addr) <= 0) {
                LOG_ERROR("transport_open: Invalid IPv6 bind address: %s", bind_ip);
                return -EINVAL;
            }
        } else {
            sa6->sin6_addr = in6addr_any;
        }
        addr_len = sizeof(struct sockaddr_in6);
    } else {
        domain = AF_INET;
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&addr;
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        if (bind_ip && bind_ip[0] != '\0' && strcmp(bind_ip, "0.0.0.0") != 0) {
            if (inet_pton(AF_INET, bind_ip, &sa4->sin_addr) <= 0) {
                LOG_ERROR("transport_open: Invalid IPv4 bind address: %s", bind_ip);
                return -EINVAL;
            }
        } else {
            sa4->sin_addr.s_addr = INADDR_ANY;
        }
        addr_len = sizeof(struct sockaddr_in);
    }

    int fd = socket(domain, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        /* Fallback if combined flags are unsupported on older kernels */
        fd = socket(domain, SOCK_DGRAM, 0);
        if (fd < 0) {
            LOG_ERROR("transport_open: socket creation failed: %s", strerror(errno));
            return -errno;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        flags = fcntl(fd, F_GETFD, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
        }
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
        LOG_ERROR("transport_open: bind failed on port %u: %s", port, strerror(errno));
        int err = -errno;
        close(fd);
        return err;
    }

    LOG_INFO("transport_open: Bound UDP socket fd=%d to port %u", fd, port);
    return fd;
}

/* =========================================================================
 * transport_send
 *
 * Send a datagram out over the UDP transport socket.
 *
 * INPUT:
 *   fd   : bound socket descriptor.
 *   dest : target endpoint (IP + Port).
 *   buf  : network wire buffer to send.
 *   len  : length of buffer in bytes.
 *
 * RETURN:
 *   Bytes sent (>= 0), 0 if socket buffer full (EAGAIN), or negative errno on error.
 * ========================================================================= */
ssize_t transport_send(int fd, const vpn_endpoint_t *dest, const uint8_t *buf, size_t len) {
    if (fd < 0 || !dest || !buf || len == 0) {
        return -EINVAL;
    }

    if (len > VPN_MAX_PACKET_SIZE) {
        LOG_WARN("transport_send: Packet size %zu exceeds max %d", len, VPN_MAX_PACKET_SIZE);
        return -EMSGSIZE;
    }

    ssize_t sent = sendto(fd, buf, len, 0, (const struct sockaddr *)&dest->addr, dest->addr_len);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return 0; /* Socket output queue full or interrupted by signal */
        }
        LOG_ERROR("transport_send: sendto error: %s", strerror(errno));
        return -errno;
    }

    return sent;
}

/* =========================================================================
 * transport_recv
 *
 * Receive a single UDP datagram from the non-blocking socket.
 *
 * INPUT:
 *   fd      : bound UDP socket descriptor.
 *   src     : pointer to output structure receiving sender's IP/port.
 *   buf     : destination memory buffer.
 *   max_len : buffer capacity.
 *
 * RETURN:
 *   Number of bytes received (> 0), 0 if no packet waiting (EAGAIN/EWOULDBLOCK),
 *   or negative errno on system socket error.
 * ========================================================================= */
ssize_t transport_recv(int fd, vpn_endpoint_t *src, uint8_t *buf, size_t max_len) {
    if (fd < 0 || !buf || max_len == 0) {
        return -EINVAL;
    }

    socklen_t addr_len = sizeof(struct sockaddr_storage);
    struct sockaddr_storage temp_addr;
    memset(&temp_addr, 0, sizeof(temp_addr));

    ssize_t n = recvfrom(fd, buf, max_len, 0, (struct sockaddr *)&temp_addr, &addr_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return 0; /* No datagram currently ready on non-blocking socket */
        }
        LOG_ERROR("transport_recv: recvfrom error: %s", strerror(errno));
        return -errno;
    }

    if (src) {
        src->addr = temp_addr;
        src->addr_len = addr_len;
    }

    return n;
}

/* =========================================================================
 * transport_close
 *
 * Close the socket file descriptor and reset pointer to -1.
 * ========================================================================= */
void transport_close(int *fd) {
    if (fd && *fd >= 0) {
        LOG_INFO("transport_close: Closing socket fd=%d", *fd);
        close(*fd);
        *fd = -1;
    }
}

