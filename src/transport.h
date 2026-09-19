#ifndef VPN_TRANSPORT_H
#define VPN_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "config.h"

#ifdef __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

typedef struct {
    struct sockaddr_storage addr;
    socklen_t addr_len;
} vpn_endpoint_t;

/**
 * Parse an IP:port string (e.g. "127.0.0.1:51820" or "[::1]:51820") into an endpoint.
 * 
 * @param str       Input address string.
 * @param endpoint  Output endpoint structure.
 * @return          0 on success, negative error code on failure.
 */
int endpoint_parse(const char *str, vpn_endpoint_t *endpoint);

/**
 * Format an endpoint structure into an "ip:port" string.
 * 
 * @param endpoint  Input endpoint.
 * @param buf       Output string buffer.
 * @param buf_len   Length of string buffer.
 * @return          0 on success, negative error code on failure.
 */
int endpoint_to_string(const vpn_endpoint_t *endpoint, char *buf, size_t buf_len);

/**
 * Check if two endpoints are identical in IP address and port.
 * 
 * @param a First endpoint.
 * @param b Second endpoint.
 * @return  1 if identical, 0 if different or invalid.
 */
int endpoint_equal(const vpn_endpoint_t *a, const vpn_endpoint_t *b);

/**
 * Create, configure, and bind a non-blocking UDP socket.
 * 
 * @param bind_ip  IP address to bind to (e.g. "0.0.0.0" or "::"), or NULL for wildcard.
 * @param port     UDP port number to bind to (e.g. 51820, or 0 for ephemeral).
 * @return         Bound socket file descriptor on success, negative error code on failure.
 */
int transport_open(const char *bind_ip, uint16_t port);

/**
 * Send a datagram over the UDP transport.
 * 
 * @param fd        Socket file descriptor.
 * @param dest      Destination endpoint.
 * @param buf       Data buffer to transmit.
 * @param len       Length of data buffer.
 * @return          Number of bytes sent, or negative error code on failure.
 */
ssize_t transport_send(int fd, const vpn_endpoint_t *dest, const uint8_t *buf, size_t len);

/**
 * Receive a datagram from the UDP transport.
 * 
 * @param fd        Socket file descriptor.
 * @param src       Output source endpoint.
 * @param buf       Destination data buffer.
 * @param max_len   Capacity of destination data buffer.
 * @return          Number of bytes received, 0 if EAGAIN (no data ready), or negative error code.
 */
ssize_t transport_recv(int fd, vpn_endpoint_t *src, uint8_t *buf, size_t max_len);

/**
 * Close a transport socket.
 * 
 * @param fd  Pointer to socket file descriptor (will be set to -1).
 */
void transport_close(int *fd);

#endif /* VPN_TRANSPORT_H */
