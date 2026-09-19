#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    char line[1024];
    int highest = -1;
    int counter, window_size;
    int *seen = NULL; /* allocated after WINDOW is parsed */

    while (fgets(line, sizeof line, stdin)) {
        if (line[0] == '\n' || line[0] == 0) continue;

        if (strncmp(line, "WINDOW ", 7) == 0) {
            sscanf(line, "WINDOW %d", &window_size);
            seen = calloc(window_size, sizeof(int)); /* allocate only now */

        } else if (strncmp(line, "RECV ", 5) == 0) {
            sscanf(line, "RECV %d", &counter);

            if (counter > highest) {
                /* New high-water mark.
                   Clear every slot from old_highest+1 up to counter.
                   This prevents stale "seen" marks from past window passes. */
                int old_highest = highest;
                for (int i = old_highest + 1; i <= counter; i++) {
                    seen[i % window_size] = 0;
                }
                seen[counter % window_size] = 1;
                highest = counter;
                printf("OK\n");

            } else if (counter > highest - window_size) {
                /* Inside the window. Check if already seen. */
                if (seen[counter % window_size] == 0) {
                    seen[counter % window_size] = 1;
                    printf("OK\n");
                } else {
                    printf("REPLAY\n");
                }

            } else {
                /* Too old — outside the window entirely. */
                printf("REPLAY\n");
            }
        }
    }

    free(seen);
    return 0;
}
