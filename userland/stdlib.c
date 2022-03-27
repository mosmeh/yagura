#include "stdlib.h"
#include "syscall.h"
#include <common/extra.h>
#include <common/string.h>
#include <common/syscall.h>
#include <stdalign.h>
#include <stdint.h>

noreturn void panic(const char* message, const char* file, size_t line) {
    printf("%s at %s:%u\n", message, file, line);
    exit(1);
}

#define MALLOC_HEAP_SIZE 0x100000

void malloc_init(malloc_ctx* ctx) {
    void* heap = mmap(NULL, MALLOC_HEAP_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    ASSERT(heap != MAP_FAILED);
    ctx->heap_start = ctx->ptr = (uintptr_t)heap;
    ctx->num_allocs = 0;
}

void* aligned_alloc(malloc_ctx* ctx, size_t alignment, size_t size) {
    if (size == 0)
        return NULL;

    uintptr_t aligned_ptr = round_up(ctx->ptr, alignment);
    uintptr_t next_ptr = aligned_ptr + size;
    if (next_ptr > ctx->heap_start + MALLOC_HEAP_SIZE)
        return NULL;

    memset((void*)aligned_ptr, 0, size);

    ctx->ptr = next_ptr;
    ++ctx->num_allocs;

    return (void*)aligned_ptr;
}

void* malloc(malloc_ctx* ctx, size_t size) {
    return aligned_alloc(ctx, alignof(max_align_t), size);
}

void free(malloc_ctx* ctx, void* ptr) {
    if (!ptr)
        return;

    ASSERT(ctx->num_allocs > 0);
    if (--ctx->num_allocs == 0)
        ctx->ptr = ctx->heap_start;
}

int printf(const char* format, ...) {
    char buf[1024];
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buf, 1024, format, args);
    va_end(args);
    puts(buf);
    return ret;
}
