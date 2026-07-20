/* VulnForge research fixture — intentional unbounded copy for static RE tests. */
#include <string.h>

void vulnerable_copy(const char *src) {
    char buf[32];
    strcpy(buf, src); /* intentional sink */
}

int main(int argc, char **argv) {
    if (argc > 1)
        vulnerable_copy(argv[1]);
    return 0;
}
