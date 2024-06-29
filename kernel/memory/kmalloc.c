#include "memory.h"
#include <common/string.h>
#include <kernel/panic.h>

void* kmalloc(size_t size) {
    void* addr = vm_alloc(size, VM_READ | VM_WRITE);
    return IS_OK(addr) ? addr : NULL;
}

void* kaligned_alloc(size_t alignment, size_t size) {
    ASSERT(alignment <= PAGE_SIZE);
    return kmalloc(size); // kmalloc already returns page-aligned addresses
}

void* krealloc(void* ptr, size_t new_size) {
    if (!ptr)
        return kmalloc(new_size);
    void* addr = vm_resize(ptr, new_size);
    return IS_OK(addr) ? addr : NULL;
}

void kfree(void* ptr) {
    if (ptr)
        ASSERT_OK(vm_free(ptr));
}

char* kstrdup(const char* src) {
    if (!src)
        return NULL;

    size_t len = strlen(src);
    char* buf = kmalloc((len + 1) * sizeof(char));
    if (!buf)
        return NULL;

    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}

char* kstrndup(const char* src, size_t n) {
    if (!src)
        return NULL;

    size_t len = strnlen(src, n);
    char* buf = kmalloc((len + 1) * sizeof(char));
    if (!buf)
        return NULL;

    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}
