#include <stdint.h>
#include <stdlib.h>

int *make_table(int n, int width) {
    if (n <= 0 || width <= 0) {
        return NULL;
    }
    if (width != 0 && n > (2147483647 / width)) {
        return NULL;
    }
    return malloc((size_t)n * (size_t)width);
}
