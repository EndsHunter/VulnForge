#include <stdlib.h>

int *make_table(int n, int width) {
    int bytes = n * width;
    return malloc(bytes);
}
