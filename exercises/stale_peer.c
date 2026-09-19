#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[1024];
    long long now = 0;
    long long stale_threshold = 0;

    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == 0) continue;

        if (strncmp(line, "NOW ", 4) == 0) {
            now = strtoll(line + 4, NULL, 10);
        } else if (strncmp(line, "STALE ", 6) == 0) {
            stale_threshold = strtoll(line + 6, NULL, 10);
        } else if (strncmp(line, "PEER ", 5) == 0) {
            char name[128];
            char ts_str[64];
            if (sscanf(line, "PEER %127s %63s", name, ts_str) == 2) {
                long long last_handshake_ts = strtoll(ts_str, NULL, 10);
                long long elapsed = now - last_handshake_ts;

                /* elapsed == stale_threshold counts as ACTIVE */
                if (elapsed <= stale_threshold) {
                    printf("ACTIVE\n");
                } else {
                    printf("STALE\n");
                }
            }
        }
    }

    return 0;
}
