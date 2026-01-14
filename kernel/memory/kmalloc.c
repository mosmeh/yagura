#include <common/integer.h>
#include <common/string.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>

void* kmalloc(size_t size) {
    size_t npages = DIV_CEIL(size, PAGE_SIZE);

    struct vm_obj* anon FREE(vm_obj) = anon_create();
    if (IS_ERR(ASSERT(anon)))
        return NULL;

    unsigned char* addr =
        vm_obj_map(anon, 0, npages, VM_READ | VM_WRITE | VM_SHARED);
    if (IS_ERR(ASSERT(addr)))
        return NULL;

    int rc =
        vm_populate(addr, addr + (npages << PAGE_SHIFT), VM_READ | VM_WRITE);
    if (IS_ERR(rc)) {
        vm_obj_unmap(addr);
        return NULL;
    }

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

    SCOPED_LOCK(vm, kernel_vm);

    struct vm_region* region = vm_find(kernel_vm, ptr);
    ASSERT(region);
    ASSERT(ptr == vm_region_to_virt(region));

    size_t new_npages = DIV_CEIL(new_size, PAGE_SIZE);
    size_t old_npages = region->end - region->start;
    if (new_npages == old_npages)
        return ptr;

    int rc = vm_region_resize(region, new_npages);
    if (IS_ERR(rc))
        return NULL;

    void* end = (unsigned char*)ptr + (new_npages << PAGE_SHIFT);
    rc = vm_populate(ptr, end, region->flags);
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
