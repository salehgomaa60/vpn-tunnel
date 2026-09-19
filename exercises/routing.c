#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_ROUTES 128

/* TODO (tun-interface): implement per the lesson description. */

struct Route {
    char name[64];
    uint32_t network;
    uint32_t mask;
    int prefix;
};

// Convert IP address string (e.g. "192.168.1.1") into a 32-bit integer in host byte order
uint32_t parse_ip(const char *str) {
    int a, b, c, d;
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    return ((uint32_t)a << 24) |
           ((uint32_t)b << 16) |
           ((uint32_t)c << 8)  |
           ((uint32_t)d);
}

// Convert CIDR notation (e.g. "10.0.0.0/24") into network address + subnet mask
void parse_cidr(const char *str, uint32_t *network, uint32_t *mask, int *prefix) {
    char ip_string[32];
    sscanf(str, "%31[^/]/%d", ip_string, prefix);
    uint32_t ip = parse_ip(ip_string);

    if (*prefix == 0)
        *mask = 0;
    else
        *mask = 0xFFFFFFFFu << (32 - *prefix);

    *network = ip & *mask;
}

int main(void) {
    char line[1024];
    struct Route routes[MAX_ROUTES];
    int route_count = 0;

    while (fgets(line, sizeof line, stdin)) {
        if (line[0] == '\n' || line[0] == 0) continue;

        /* Register a peer route */
        if (strncmp(line, "PEER ", 5) == 0) {
            char name[64];
            char cidr[64];

            sscanf(line, "PEER %63s %63s", name, cidr);

            strcpy(routes[route_count].name, name);

            parse_cidr(
                cidr,
                &routes[route_count].network,
                &routes[route_count].mask,
                &routes[route_count].prefix
            );

            route_count++;
        }
        /* Query a destination IP (Longest Prefix Match) */
        else if (strncmp(line, "ROUTE ", 6) == 0) {
            char ip_string[64];

            sscanf(line, "ROUTE %63s", ip_string);

            uint32_t ip = parse_ip(ip_string);

            int best_route = -1;
            int best_prefix = -1;

            for (int i = 0; i < route_count; i++) {
                if ((ip & routes[i].mask) == routes[i].network) {
                    if (routes[i].prefix > best_prefix) {
                        best_prefix = routes[i].prefix;
                        best_route = i;
                    }
                }
            }

            if (best_route == -1)
                printf("DROP\n");
            else
                printf("%s\n", routes[best_route].name);
        }
    }
    return 0;
}
