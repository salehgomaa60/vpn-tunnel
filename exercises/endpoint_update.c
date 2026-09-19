#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PEERS 512
#define MAX_STR_LEN 128

typedef struct {
    char peer[MAX_STR_LEN];
    char endpoint[MAX_STR_LEN];
} PeerEndpoint;

int main(void) {
    char line[1024];
    PeerEndpoint peers[MAX_PEERS];
    int peer_count = 0;

    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == 0) continue;

        char peer[MAX_STR_LEN];
        char endpoint[MAX_STR_LEN];

        if (sscanf(line, "RECV %127s %127s", peer, endpoint) == 2) {
            int found_idx = -1;

            for (int i = 0; i < peer_count; i++) {
                if (strcmp(peers[i].peer, peer) == 0) {
                    found_idx = i;
                    break;
                }
            }

            if (found_idx == -1) {
                /* First time seeing this peer */
                if (peer_count < MAX_PEERS) {
                    strncpy(peers[peer_count].peer, peer, MAX_STR_LEN - 1);
                    peers[peer_count].peer[MAX_STR_LEN - 1] = '\0';

                    strncpy(peers[peer_count].endpoint, endpoint, MAX_STR_LEN - 1);
                    peers[peer_count].endpoint[MAX_STR_LEN - 1] = '\0';

                    peer_count++;
                }
                printf("LEARNED %s %s\n", peer, endpoint);
            } else {
                /* Peer was seen before */
                if (strcmp(peers[found_idx].endpoint, endpoint) == 0) {
                    printf("OK\n");
                } else {
                    /* Roamed to a new endpoint: update recorded endpoint */
                    strncpy(peers[found_idx].endpoint, endpoint, MAX_STR_LEN - 1);
                    peers[found_idx].endpoint[MAX_STR_LEN - 1] = '\0';
                    printf("ROAMED %s %s\n", peer, endpoint);
                }
            }
        }
    }

    return 0;
}
