/*
 * routing.c — IPv4 Address Parsing and CIDR Cryptographic Routing Math
 *
 * EDUCATIONAL OVERVIEW & SUBNET MATH
 * ----------------------------------
 * In WireGuard and our VPN tunnel, IP routing is tied directly to peer identity ("Cryptographic Routing").
 * Every peer configuration specifies an "AllowedIPs" list in CIDR notation (e.g., "10.0.0.2/32" or "192.168.1.0/24").
 *
 * 32-bit IPv4 Representation:
 *   An IPv4 address "A.B.C.D" is stored as a 32-bit unsigned integer:
 *     (A << 24) | (B << 16) | (C << 8) | D
 *
 * Subnet Mask Math:
 *   Prefix length N (0 to 32) creates a 32-bit mask with N leading 1s:
 *     Prefix /24 -> Mask 0xFFFFFF00 (255.255.255.0)
 *     Prefix /32 -> Mask 0xFFFFFFFF (255.255.255.255)
 *
 * Match Verification:
 *   An IP matches a CIDR subnet if: `(ip & mask) == network`
 */

#include "routing.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* =========================================================================
 * vpn_ip_parse
 *
 * Parse an IPv4 string ("192.168.1.1") into a 32-bit big-endian integer.
 * ========================================================================= */
uint32_t vpn_ip_parse(const char *str) {
    if (!str) return 0;
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return 0;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return 0;
    }
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
}

/* =========================================================================
 * vpn_ip_to_string
 *
 * Format a 32-bit IPv4 integer back into "A.B.C.D" string notation.
 * ========================================================================= */
int vpn_ip_to_string(uint32_t ip, char *buf, size_t buf_len) {
    if (!buf || buf_len < 16) {
        return -EINVAL;
    }
    int written = snprintf(buf, buf_len, "%u.%u.%u.%u",
                           (ip >> 24) & 0xFF,
                           (ip >> 16) & 0xFF,
                           (ip >> 8)  & 0xFF,
                           ip & 0xFF);
    if (written < 0 || (size_t)written >= buf_len) {
        return -ENOSPC;
    }
    return 0;
}

/* =========================================================================
 * vpn_cidr_parse
 *
 * Parse a CIDR notation string (e.g. "10.0.0.0/24" or "10.0.0.2/32") into a `vpn_cidr_t`.
 * Calculates the bitwise `mask` and canonical `network` address.
 * ========================================================================= */
int vpn_cidr_parse(const char *str, vpn_cidr_t *cidr) {
    if (!str || !cidr) {
        return -EINVAL;
    }

    char ip_buf[32] = {0};
    int prefix = 32;

    const char *slash = strchr(str, '/');
    if (slash) {
        size_t len = slash - str;
        if (len == 0 || len >= sizeof(ip_buf)) {
            return -EINVAL;
        }
        memcpy(ip_buf, str, len);
        prefix = atoi(slash + 1);
    } else {
        snprintf(ip_buf, sizeof(ip_buf), "%s", str);
    }

    if (prefix < 0 || prefix > 32) {
        return -EINVAL;
    }

    uint32_t ip = vpn_ip_parse(ip_buf);
    uint32_t mask;
    if (prefix == 0) {
        mask = 0;
    } else if (prefix == 32) {
        mask = 0xFFFFFFFFu;
    } else {
        mask = 0xFFFFFFFFu << (32 - prefix);
    }

    cidr->network = ip & mask;
    cidr->mask = mask;
    cidr->prefix_len = prefix;

    return 0;
}

/* =========================================================================
 * vpn_cidr_match
 *
 * Check whether a target IPv4 address belongs to a CIDR range.
 * Formula: `(ip & cidr->mask) == cidr->network`
 * ========================================================================= */
int vpn_cidr_match(const vpn_cidr_t *cidr, uint32_t ip) {
    if (!cidr) return 0;
    return (ip & cidr->mask) == cidr->network;
}

