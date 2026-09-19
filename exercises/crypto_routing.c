#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PEERS 256
#define MAX_CIDRS_PER_PEER 128

typedef struct {
    uint32_t network;
    uint32_t mask;
} CIDR;

typedef struct {
    char pubkey[128];
    CIDR allowed_ips[MAX_CIDRS_PER_PEER];
    int cidr_count;
} Peer;

static uint32_t parse_ip(const char *str) {
    unsigned int a, b, c, d;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
}

static CIDR parse_cidr(const char *str) {
    CIDR cidr = {0, 0};
    char ip_buf[64] = {0};
    int prefix = 32;

    const char *slash = strchr(str, '/');
    if (slash) {
        size_t len = slash - str;
        if (len < sizeof(ip_buf)) {
            strncpy(ip_buf, str, len);
            ip_buf[len] = '\0';
        }
        prefix = atoi(slash + 1);
    } else {
        strncpy(ip_buf, str, sizeof(ip_buf) - 1);
    }

    uint32_t ip = parse_ip(ip_buf);
    uint32_t mask;
    if (prefix <= 0) {
        mask = 0;
    } else if (prefix >= 32) {
        mask = 0xFFFFFFFFu;
    } else {
        mask = 0xFFFFFFFFu << (32 - prefix);
    }

    cidr.mask = mask;
    cidr.network = ip & mask;
    return cidr;
}

static int matches_cidr(uint32_t ip, CIDR cidr) {
    return (ip & cidr.mask) == cidr.network;
}

static int peer_allows_ip(const Peer *peer, uint32_t ip) {
    for (int i = 0; i < peer->cidr_count; i++) {
        if (matches_cidr(ip, peer->allowed_ips[i])) {
            return 1;
        }
    }
    return 0;
}

int main(void) {
    char line[2048];
    Peer peers[MAX_PEERS];
    int peer_count = 0;

    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == 0) continue;

        if (strncmp(line, "PEER ", 5) == 0) {
            char pubkey[128];
            char cidrs_str[1024];

            if (sscanf(line, "PEER %127s %1023s", pubkey, cidrs_str) == 2) {
                if (peer_count < MAX_PEERS) {
                    Peer *p = &peers[peer_count++];
                    strncpy(p->pubkey, pubkey, sizeof(p->pubkey) - 1);
                    p->pubkey[sizeof(p->pubkey) - 1] = '\0';
                    p->cidr_count = 0;

                    char *token = strtok(cidrs_str, ",");
                    while (token && p->cidr_count < MAX_CIDRS_PER_PEER) {
                        p->allowed_ips[p->cidr_count++] = parse_cidr(token);
                        token = strtok(NULL, ",");
                    }
                }
            }
        } else if (strncmp(line, "OUT ", 4) == 0) {
            char dest_ip_str[64];
            if (sscanf(line, "OUT %63s", dest_ip_str) == 1) {
                uint32_t dest_ip = parse_ip(dest_ip_str);
                int found = 0;

                /* Scan peers in definition order; output first match */
                for (int i = 0; i < peer_count; i++) {
                    if (peer_allows_ip(&peers[i], dest_ip)) {
                        printf("%s\n", peers[i].pubkey);
                        found = 1;
                        break;
                    }
                }

                if (!found) {
                    printf("DROP\n");
                }
            }
        } else if (strncmp(line, "IN ", 3) == 0) {
            char peer_pub[128];
            char src_ip_str[64];
            if (sscanf(line, "IN %127s %63s", peer_pub, src_ip_str) == 2) {
                uint32_t src_ip = parse_ip(src_ip_str);
                int found_peer = 0;
                int allowed = 0;

                for (int i = 0; i < peer_count; i++) {
                    if (strcmp(peers[i].pubkey, peer_pub) == 0) {
                        found_peer = 1;
                        if (peer_allows_ip(&peers[i], src_ip)) {
                            allowed = 1;
                        }
                        break;
                    }
                }

                if (found_peer && allowed) {
                    printf("OK\n");
                } else {
                    printf("DROP\n");
                }
            }
        }
    }

    return 0;
}
