#include "memory.h"
#include <common/string.h>
#include <kernel/gdt.h>
#include <kernel/panic.h>

void* kmalloc(size_t size) {
    size_t npages = DIV_CEIL(size, PAGE_SIZE);
    /*if (!page_commit(num_pages))
        return NULL;*/

    struct vm_obj* anon = anon_create();
    if (IS_ERR(anon))
        return NULL;

    spinlock_lock(&kernel_vm->lock);
    struct vm_region* region = vm_alloc(kernel_vm, npages);
    if (IS_ERR(region)) {
        spinlock_unlock(&kernel_vm->lock);
        vm_obj_unref(anon);
        return NULL;
    }

    ASSERT_OK(vm_region_set_flags(region, 0, npages,
                                  VM_READ | VM_WRITE | VM_SHARED, ~0));
    vm_region_set_obj(region, anon, 0);

    spinlock_unlock(&kernel_vm->lock);

    return vm_region_to_virt(region);
}

void* kaligned_alloc(size_t alignment, size_t size) {
    ASSERT(PAGE_SIZE % alignment == 0);
    return kmalloc(size); // kmalloc already returns page-aligned addresses
}

void* krealloc(void* ptr, size_t new_size) {
    if (!ptr)
        return kmalloc(new_size);

    spinlock_lock(&kernel_vm->lock);

    struct vm_region* region = vm_find(kernel_vm, ptr);
    ASSERT(region);
    ASSERT(ptr == vm_region_to_virt(region));

    size_t new_npages = DIV_CEIL(new_size, PAGE_SIZE);
    size_t old_npages = region->end - region->start;
    if (new_npages == old_npages) {
        spinlock_unlock(&kernel_vm->lock);
        return ptr;
    }
    /*if (new_npages < old_npages)
        page_uncommit(old_npages - new_npages);
    else if (!page_commit(new_npages - old_npages))
        return NULL;*/

    int rc = vm_region_resize(region, new_npages);
    spinlock_unlock(&kernel_vm->lock);
    if (IS_ERR(rc))
        return NULL;

    // The region might have been moved
    return vm_region_to_virt(region);
}

void kfree(void* ptr) {
    if (!ptr)
        return;

    spinlock_lock(&kernel_vm->lock);
    struct vm_region* region = vm_find(kernel_vm, ptr);
    ASSERT(region);
    ASSERT(ptr == vm_region_to_virt(region));
    ASSERT_OK(vm_region_free(region, 0, region->end - region->start));
    spinlock_unlock(&kernel_vm->lock);
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

void* phys_map(uintptr_t phys_addr, size_t size, unsigned vm_flags) {
    uintptr_t aligned_addr = ROUND_DOWN(phys_addr, PAGE_SIZE);
    size_t npages = DIV_CEIL(phys_addr - aligned_addr + size, PAGE_SIZE);
    struct vm_obj* phys = phys_create(aligned_addr, npages);
    if (IS_ERR(phys))
        return ERR_CAST(phys);

    spinlock_lock(&kernel_vm->lock);
    struct vm_region* region = vm_alloc(kernel_vm, npages);
    if (IS_ERR(region)) {
        spinlock_unlock(&kernel_vm->lock);
        vm_obj_unref(phys);
        return ERR_CAST(region);
    }

    ASSERT_OK(vm_region_set_flags(region, 0, npages, vm_flags | VM_SHARED, ~0));
    vm_region_set_obj(region, phys, 0);

    spinlock_unlock(&kernel_vm->lock);

    return (unsigned char*)vm_region_to_virt(region) +
           (phys_addr - aligned_addr);
}

void phys_unmap(void* virt_addr) {
    if (!virt_addr)
        return;

    spinlock_lock(&kernel_vm->lock);
    struct vm_region* region = vm_find(kernel_vm, virt_addr);
    ASSERT(region);
    ASSERT_OK(vm_region_free(region, 0, region->end - region->start));
    spinlock_unlock(&kernel_vm->lock);
}
