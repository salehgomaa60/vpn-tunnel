#ifndef VPN_ROUTING_H
#define VPN_ROUTING_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t network;
    uint32_t mask;
    int prefix_len;
} vpn_cidr_t;

/**
 * Parse an IPv4 string "A.B.C.D" into a 32-bit integer in host byte order.
 */
uint32_t vpn_ip_parse(const char *str);

/**
 * Format a 32-bit IPv4 integer into "A.B.C.D" string.
 */
int vpn_ip_to_string(uint32_t ip, char *buf, size_t buf_len);

/**
 * Parse CIDR notation (e.g. "10.0.0.0/24" or "192.168.1.1/32") into a vpn_cidr_t.
 */
int vpn_cidr_parse(const char *str, vpn_cidr_t *cidr);

/**
 * Check whether an IP matches a CIDR range.
 */
int vpn_cidr_match(const vpn_cidr_t *cidr, uint32_t ip);

#endif /* VPN_ROUTING_H */
