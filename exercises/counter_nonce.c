#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    char line[1024];
    while (fgets(line, sizeof line, stdin)) {
        if (line[0] == '\n' || line[0] == 0) continue;

        char *ptr = strstr(line, "NONCE");
        if (ptr) {
            ptr += 5;
            uint64_t counter = strtoull(ptr, NULL, 10);
            uint8_t nonce[12] = {0};

            /* 4 bytes of zero: nonce[0..3] remain 0 */
            /* 8 bytes of counter in little-endian order: */
            for (int i = 0; i < 8; i++) {
                nonce[4 + i] = (uint8_t)((counter >> (8 * i)) & 0xFF);
            }

            /* Print 12 bytes as 24 hex characters */
            for (int i = 0; i < 12; i++) {
                printf("%02x", nonce[i]);
            }
            printf("\n");
        }
    }
    return 0;
}
