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

void kmalloc_init(void) { mutex_init(&lock); }

void* kaligned_alloc(size_t alignment, size_t size) {
    if (size == 0)
        return NULL;

    mutex_lock(&lock);

    uintptr_t aligned_ptr = round_up(heap_ptr, alignment);
    uintptr_t next_ptr = aligned_ptr + size;
    KASSERT(next_ptr <= 0xffc00000); // last 4MiB is for recursive mapping

    mem_map_virtual_addr_range_to_any_pages(aligned_ptr, next_ptr, MEM_WRITE);
    memset((void*)aligned_ptr, 0, size);

    heap_ptr = next_ptr;

    mutex_unlock(&lock);
    return (void*)aligned_ptr;
}

void* kmalloc(size_t size) {
    return kaligned_alloc(alignof(max_align_t), size);
}

char* kstrdup(const char* src) {
    char* buf = kmalloc(strlen(src) * sizeof(char));
    strcpy(buf, src);
    return buf;
}

char* kstrndup(const char* src, size_t n) {
    char* buf = kmalloc(strnlen(src, n) * sizeof(char));
    strncpy(buf, src, n);
    return buf;
}
