#include <panic.h>
#include <stdlib.h>

int main(void) {
    free(malloc(0));

    for (size_t i = 0; i < 10000; ++i) {
        void* buf = malloc(1);
        ASSERT(buf);
        void* buf2 = malloc(100000);
        ASSERT(buf2);
        free(buf);
        free(buf2);
    }

    return EXIT_SUCCESS;
}
