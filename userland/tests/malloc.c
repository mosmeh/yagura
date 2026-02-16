#include <panic.h>
#include <stdlib.h>

int main(void) {
    free(malloc(0));

    for (size_t i = 0; i < 10000; ++i) {
        void* buf = ASSERT(malloc(1));
        void* buf2 = ASSERT(malloc(100000));
        free(buf);
        free(buf2);
    }

    return EXIT_SUCCESS;
}
