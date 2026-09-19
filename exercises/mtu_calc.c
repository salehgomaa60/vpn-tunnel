#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == 0) continue;

        int outer_mtu = 0;
        if (sscanf(line, "INNER_MTU %d", &outer_mtu) == 1) {
            int inner = outer_mtu - 60;
            if (inner < 576) {
                printf("INVALID\n");
            } else {
                printf("%d\n", inner);
            }
        }
    }
    return 0;
}
