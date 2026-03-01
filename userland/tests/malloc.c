#include <panic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    free(malloc(0));

    for (size_t i = 0; i < 10000; ++i) {
        void* buf = ASSERT(malloc(1));
        ASSERT((uintptr_t)buf % _Alignof(max_align_t) == 0);
        void* buf2 = ASSERT(malloc(100000));
        ASSERT((uintptr_t)buf2 % _Alignof(max_align_t) == 0);
        free(buf);
        free(buf2);
    }

    void* p = ASSERT(aligned_alloc(64, 5000));
    ASSERT(((uintptr_t)p % 64) == 0);
    free(p);

    p = ASSERT(malloc(100));
    strcpy(p, "Hello, world!");
    p = ASSERT(realloc(p, 200));
    ASSERT(!strcmp(p, "Hello, world!"));
    p = ASSERT(realloc(p, 6000));
    ASSERT(!strcmp(p, "Hello, world!"));
    p = ASSERT(realloc(p, 50));
    ASSERT(!strcmp(p, "Hello, world!"));
    free(p);

    p = ASSERT(aligned_alloc(2048, 16));
    ASSERT(((uintptr_t)p % 2048) == 0);
    p = ASSERT(realloc(p, 7000));
    ASSERT(((uintptr_t)p % _Alignof(max_align_t)) == 0);
    free(p);

    return EXIT_SUCCESS;
}
