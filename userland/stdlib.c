#include "stdlib.h"
#include "syscall.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/mman.h>
#include <kernel/api/syscall.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

noreturn void panic(const char* message, const char* file, size_t line) {
    printf("%s at %s:%u\n", message, file, line);
    exit(1);
}

#define MALLOC_HEAP_SIZE 0x100000

static struct {
    bool initialized;
    uintptr_t heap_start;
    uintptr_t ptr;
    size_t num_allocs;
} malloc_ctx;

static void malloc_init_if_needed(void) {
    if (malloc_ctx.initialized)
        return;

    void* heap = mmap(NULL, MALLOC_HEAP_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    ASSERT(heap != MAP_FAILED);
    malloc_ctx.heap_start = malloc_ctx.ptr = (uintptr_t)heap;
    malloc_ctx.num_allocs = 0;
    malloc_ctx.initialized = true;
}

void* aligned_alloc(size_t alignment, size_t size) {
    if (size == 0)
        return NULL;

    malloc_init_if_needed();

    uintptr_t aligned_ptr = round_up(malloc_ctx.ptr, alignment);
    uintptr_t next_ptr = aligned_ptr + size;
    if (next_ptr > malloc_ctx.heap_start + MALLOC_HEAP_SIZE)
        return NULL;

    memset((void*)aligned_ptr, 0, size);

    malloc_ctx.ptr = next_ptr;
    ++malloc_ctx.num_allocs;

    return (void*)aligned_ptr;
}

void* malloc(size_t size) { return aligned_alloc(alignof(max_align_t), size); }

void free(void* ptr) {
    if (!ptr)
        return;

    ASSERT(malloc_ctx.initialized);
    ASSERT(malloc_ctx.num_allocs > 0);
    if (--malloc_ctx.num_allocs == 0)
        malloc_ctx.ptr = malloc_ctx.heap_start;
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
