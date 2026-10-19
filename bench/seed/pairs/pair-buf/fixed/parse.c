#include <string.h>

void copy_name(char *dst, size_t cap, const char *src) {
    if (cap == 0) {
        return;
    }
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}
