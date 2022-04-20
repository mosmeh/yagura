#include "kmalloc.h"
#include "api/err.h"
#include "boot_defs.h"
#include "lock.h"
#include "memory.h"
#include "memory/memory.h"
#include "panic.h"
#include "system.h"
#include <common/extra.h>
#include <common/string.h>
#include <stdalign.h>
#include <string.h>

#define KMALLOC_HEAP_SIZE 0x1000000

static mutex lock;

static uintptr_t heap_start;
static uintptr_t ptr;

void kmalloc_init(void) {
    mutex_init(&lock);

    heap_start = ptr =
        memory_alloc_kernel_virtual_addr_range(KMALLOC_HEAP_SIZE);
    ASSERT_OK(heap_start);
    ASSERT_OK(memory_map_to_anonymous_region(heap_start, KMALLOC_HEAP_SIZE,
                                             MEMORY_WRITE | MEMORY_GLOBAL));
}

void* kaligned_alloc(size_t alignment, size_t size) {
    if (size == 0)
        return NULL;

    mutex_lock(&lock);

    uintptr_t aligned_ptr = round_up(ptr, alignment);
    uintptr_t next_ptr = aligned_ptr + size;
    if (next_ptr > heap_start + KMALLOC_HEAP_SIZE)
        return NULL;

    memset((void*)aligned_ptr, 0, size);

    ptr = next_ptr;

    mutex_unlock(&lock);
    return (void*)aligned_ptr;
}

void* kmalloc(size_t size) {
    return kaligned_alloc(alignof(max_align_t), size);
}

char* kstrdup(const char* src) {
    size_t len = strlen(src);
    char* buf = kmalloc((len + 1) * sizeof(char));
    if (!buf)
        return NULL;

    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}

char* kstrndup(const char* src, size_t n) {
    size_t len = strnlen(src, n);
    char* buf = kmalloc((len + 1) * sizeof(char));
    if (!buf)
        return NULL;

    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}
