#include "kmalloc.h"
#include "boot_defs.h"
#include "memory/memory.h"
#include "panic.h"
#include "system.h"
#include <common/extra.h>
#include <common/string.h>
#include <string.h>

#define MAGIC 0x1d578e50

struct header {
    uint32_t magic;
    size_t size;
    unsigned char data[];
};

void* kaligned_alloc(size_t alignment, size_t size) {
    if (size == 0)
        return NULL;

    ASSERT(alignment <= PAGE_SIZE);

    size_t data_offset = round_up(sizeof(struct header), alignment);
    size_t real_size = data_offset + size;
    uintptr_t addr = kernel_vaddr_allocator_alloc(real_size);
    if (IS_ERR(addr))
        return NULL;
    if (IS_ERR(memory_map_to_anonymous_region(addr, real_size,
                                              MEMORY_WRITE | MEMORY_GLOBAL)))
        return NULL;

    struct header* header = (struct header*)addr;
    header->magic = MAGIC;
    header->size = real_size;

    void* ptr = (void*)((uintptr_t)addr + data_offset);
    memset(ptr, 0, size);
    return ptr;
}

void* kmalloc(size_t size) {
    return kaligned_alloc(alignof(max_align_t), size);
}

void kfree(void* ptr) {
    if (!ptr)
        return;
    uintptr_t addr = round_down((uintptr_t)ptr, PAGE_SIZE);
    if ((uintptr_t)ptr - addr < sizeof(struct header))
        addr -= PAGE_SIZE;
    struct header* header = (struct header*)addr;
    ASSERT(header->magic == MAGIC);
    size_t size = header->size;
    memory_unmap(addr, size);
    kernel_vaddr_allocator_free(addr, size);
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
