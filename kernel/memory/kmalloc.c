#include <common/integer.h>
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>

#define SLAB_SHIFT_MIN 4
static struct slab slabs[7];

void kmalloc_init(void) {
    for (size_t i = 0; i < ARRAY_SIZE(slabs); ++i) {
        size_t size = 1UL << (i + SLAB_SHIFT_MIN);
        char name[16];
        ASSERT((size_t)snprintf(name, sizeof(name), "kmalloc-%zu", size) <
               sizeof(name));
        slab_init(&slabs[i], name, _Alignof(max_align_t), size);
    }
}

void* kmalloc(size_t size) {
    return kaligned_alloc(_Alignof(max_align_t), size);
}

void* kaligned_alloc(size_t alignment, size_t size) {
    ASSERT(alignment);
    ASSERT(is_power_of_two(alignment));
    // TODO: support non-page-aligned allocations
    ASSERT(PAGE_SIZE % alignment == 0);

    if (size == 0)
        return NULL;

    if (alignment <= _Alignof(max_align_t)) {
        size_t index = ilog2(size - 1) + 1;
        index = MAX(index, SLAB_SHIFT_MIN) - SLAB_SHIFT_MIN;
        if (index < ARRAY_SIZE(slabs)) {
            void* ptr = slab_alloc(&slabs[index]);
            if (IS_ERR(ptr))
                return NULL;
            return ptr;
        }
    }

    size_t npages = DIV_CEIL(size, PAGE_SIZE);

    struct vm_obj* anon FREE(vm_obj) = ASSERT(anon_create());
    if (IS_ERR(anon))
        return NULL;

    unsigned char* addr =
        ASSERT(vm_obj_map(anon, 0, npages, VM_READ | VM_WRITE | VM_SHARED));
    if (IS_ERR(addr))
        return NULL;

    int rc = vm_populate(kernel_vm, addr, addr + (npages << PAGE_SHIFT),
                         VM_READ | VM_WRITE);
    if (IS_ERR(rc)) {
        vm_obj_unmap(addr);
        return NULL;
    }

    return addr;
}

void* krealloc(void* ptr, size_t new_size) {
    if (!ptr)
        return kmalloc(new_size);

    if (new_size == 0) {
        kfree(ptr);
        return NULL;
    }

    struct slab* slab = slab_lookup(ptr);
    if (slab) {
        if (slab->obj_size >= new_size)
            return ptr;
        void* new_ptr = kmalloc(new_size);
        if (!new_ptr)
            return NULL;
        memcpy(new_ptr, ptr, slab->obj_size);
        slab_free(slab, ptr);
        return new_ptr;
    }

    SCOPED_LOCK(vm, kernel_vm);

    struct vm_region* region = ASSERT_PTR(vm_find(kernel_vm, ptr));
    ASSERT(ptr == vm_region_to_virt(region));

    size_t new_npages = DIV_CEIL(new_size, PAGE_SIZE);
    size_t old_npages = region->end - region->start;
    if (new_npages == old_npages)
        return ptr;

    int rc = vm_region_resize(region, new_npages);
    if (IS_ERR(rc))
        return NULL;

    void* end = (unsigned char*)ptr + (new_npages << PAGE_SHIFT);
    rc = vm_populate(kernel_vm, ptr, end, region->flags);
    if (IS_ERR(rc))
        return NULL;

    return vm_region_to_virt(region); // The region might have been moved
}

void kfree(void* ptr) {
    if (!ptr)
        return;
    struct slab* slab = slab_lookup(ptr);
    if (slab)
        slab_free(slab, ptr);
    else
        vm_obj_unmap(ptr);
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
