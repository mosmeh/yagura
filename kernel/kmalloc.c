#include "kmalloc.h"
#include "boot_defs.h"
#include "lock.h"
#include "mem.h"
#include "system.h"
#include <common/extra.h>
#include <common/string.h>
#include <stdalign.h>

static mutex lock;

// kernel heap starts right after the quickmap page
static uintptr_t heap_ptr = KERNEL_VADDR + 1024 * PAGE_SIZE;
static uintptr_t current_page_start;

void kmalloc_init(void) {
    mutex_init(&lock);
    current_page_start = heap_ptr;
}

void* kaligned_alloc(size_t alignment, size_t size) {
    if (size == 0)
        return NULL;

    mutex_lock(&lock);

    uintptr_t aligned_ptr = round_up(heap_ptr, alignment);
    uintptr_t next_ptr = aligned_ptr + size;
    if (next_ptr > 0xffc00000) // last 4MiB is for recursive mapping
        return NULL;

    uintptr_t region_start =
        MAX(current_page_start, round_down(aligned_ptr, PAGE_SIZE));
    uintptr_t region_end = round_up(next_ptr, PAGE_SIZE);
    uintptr_t region_size = region_end - region_start;

    if (mem_map_to_private_anonymous_region(region_start, region_size,
                                            MEM_WRITE) < 0)
        return NULL;

    current_page_start = region_end;

    heap_ptr = next_ptr;
    mutex_unlock(&lock);

    memset((void*)aligned_ptr, 0, size);
    return (void*)aligned_ptr;
}

void* kmalloc(size_t size) {
    return kaligned_alloc(alignof(max_align_t), size);
}

char* kstrdup(const char* src) {
    char* buf = kmalloc(strlen(src) * sizeof(char));
    if (!buf)
        return NULL;

    strcpy(buf, src);
    return buf;
}

char* kstrndup(const char* src, size_t n) {
    char* buf = kmalloc(strnlen(src, n) * sizeof(char));
    if (!buf)
        return NULL;

    strncpy(buf, src, n);
    return buf;
}
