#include "vm.h"
#include <common/string.h>
#include <kernel/panic.h>

void* kmalloc(size_t size) {
    size_t npages = DIV_CEIL(size, PAGE_SIZE);

    struct vm_obj* anon FREE(vm_obj) = anon_create();
    if (IS_ERR(ASSERT(anon)))
        return NULL;

    void* addr = vm_obj_map(anon, 0, npages, VM_READ | VM_WRITE | VM_SHARED);
    if (IS_ERR(ASSERT(addr)))
        return NULL;
    return addr;
}

void* kaligned_alloc(size_t alignment, size_t size) {
    void* addr = kmalloc(size);
    // TODO: support non-page-aligned allocations
    ASSERT(((uintptr_t)addr % alignment) == 0);
    return addr;
}

void* krealloc(void* ptr, size_t new_size) {
    if (!ptr)
        return kmalloc(new_size);

    mutex_lock(&kernel_vm->lock);

    struct vm_region* region = vm_find(kernel_vm, ptr);
    ASSERT(region);
    ASSERT(ptr == vm_region_to_virt(region));

    size_t new_npages = DIV_CEIL(new_size, PAGE_SIZE);
    size_t old_npages = region->end - region->start;
    if (new_npages == old_npages) {
        mutex_unlock(&kernel_vm->lock);
        return ptr;
    }

    int rc = vm_region_resize(region, new_npages);
    mutex_unlock(&kernel_vm->lock);
    if (IS_ERR(rc))
        return NULL;

    // The region might have been moved
    return vm_region_to_virt(region);
}

void kfree(void* ptr) { vm_obj_unmap(ptr); }

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
