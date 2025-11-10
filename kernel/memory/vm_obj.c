#include "private.h"
#include "vm.h"
#include <common/string.h>
#include <kernel/panic.h>
#include <kernel/task.h>

void vm_obj_ref(struct vm_obj* obj) {
    ASSERT(obj);
    ASSERT(obj->ref_count++ > 0);
}

void vm_obj_unref(struct vm_obj* obj) {
    if (!obj)
        return;
    ASSERT(obj->ref_count > 0);
    if (--obj->ref_count > 0)
        return;

    ASSERT(!obj->shared_regions);

    const struct vm_ops* vm_ops = obj->vm_ops;
    ASSERT(vm_ops);
    ASSERT(vm_ops->destroy_obj);
    vm_ops->destroy_obj(obj);
}

void* vm_obj_map(struct vm_obj* obj, size_t offset, size_t npages,
                 unsigned flags) {
    mutex_lock(&kernel_vm->lock);

    struct vm_region* region = vm_alloc(kernel_vm, npages);
    if (IS_ERR(region)) {
        mutex_unlock(&kernel_vm->lock);
        return ERR_CAST(region);
    }

    ASSERT_OK(vm_region_set_flags(region, 0, npages, flags, ~0));
    vm_obj_ref(obj);
    vm_region_set_obj(region, obj, offset);

    mutex_unlock(&kernel_vm->lock);

    return vm_region_to_virt(region);
}

void vm_obj_unmap(void* virt_addr) {
    if (!virt_addr)
        return;

    mutex_lock(&kernel_vm->lock);
    struct vm_region* region = vm_find(kernel_vm, virt_addr);
    ASSERT(region);
    ASSERT(ROUND_DOWN((uintptr_t)virt_addr, PAGE_SIZE) ==
           (uintptr_t)vm_region_to_virt(region));
    ASSERT_OK(vm_region_free(region, 0, region->end - region->start));
    mutex_unlock(&kernel_vm->lock);
}

int vm_obj_invalidate_mappings(const struct vm_obj* obj, size_t offset,
                               size_t npages) {
    ASSERT(mutex_is_locked_by_current(&obj->lock));
    int rc = 0;
    struct vm* original_vm = vm_get_current();
    for (const struct vm_region* region = obj->shared_regions; region;
         region = region->shared_next) {
        if (region->offset + (region->end - region->start) <= offset)
            continue;
        if (region->offset >= offset + npages)
            continue;

        struct vm* vm = region->vm;
        if (vm != kernel_vm && vm != vm_get_current())
            vm_enter(vm);

        size_t region_offset = offset - region->offset;
        size_t region_npages =
            MIN(npages, region->end - region->start - region_offset);

        mutex_lock(&vm->lock);
        rc = vm_region_invalidate(region, region_offset, region_npages);
        mutex_unlock(&vm->lock);

        if (IS_ERR(rc))
            break;
    }
    vm_enter(original_vm);
    return rc;
}

struct anon {
    struct vm_obj vm_obj;
    struct page* shared_pages; // Pages referenced by VM_SHARED regions
};

static struct slab_cache anon_cache;

static void anon_destroy(struct vm_obj* obj) {
    struct anon* anon = CONTAINER_OF(obj, struct anon, vm_obj);
    pages_clear(&anon->shared_pages);
    slab_cache_free(&anon_cache, obj);
}

static struct page* zero_page;

static struct page* anon_get_page(struct vm_obj* obj, size_t index,
                                  uint32_t error_code) {
    ASSERT(mutex_is_locked_by_current(&obj->lock));
    struct anon* anon = CONTAINER_OF(obj, struct anon, vm_obj);

    struct page* page = pages_get(anon->shared_pages, index);
    if (page)
        return page;

    if (!(error_code & X86_PF_WRITE))
        return zero_page;

    // Invalidate mappings to zero_page
    int rc = vm_obj_invalidate_mappings(obj, index, 1);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    page = pages_alloc_at(&anon->shared_pages, index);
    if (IS_ERR(page))
        return page;
    page_fill(page, 0, 0, PAGE_SIZE);
    return page;
}

static const struct vm_ops anon_vm_ops = {
    .destroy_obj = anon_destroy,
    .get_page = anon_get_page,
};

struct vm_obj* anon_create(void) {
    struct anon* anon = slab_cache_alloc(&anon_cache);
    if (IS_ERR(anon))
        return ERR_CAST(anon);
    *anon = (struct anon){
        .vm_obj =
            {
                .vm_ops = &anon_vm_ops,
                .ref_count = 1,
            },
    };
    return &anon->vm_obj;
}

struct phys {
    struct vm_obj vm_obj;
    size_t start; // Start pfn (inclusive)
    size_t end;   // End pfn (exclusive)
};

static struct slab_cache phys_cache;

static void phys_destroy(struct vm_obj* obj) {
    struct phys* phys = CONTAINER_OF(obj, struct phys, vm_obj);
    slab_cache_free(&phys_cache, phys);
}

static struct page* phys_get_page(struct vm_obj* obj, size_t index,
                                  uint32_t error_code) {
    (void)error_code;
    ASSERT(mutex_is_locked_by_current(&obj->lock));
    struct phys* phys = CONTAINER_OF(obj, struct phys, vm_obj);
    size_t pfn = phys->start + index;
    if (phys->end <= pfn)
        return ERR_PTR(-EFAULT);
    return page_get(pfn);
}

static const struct vm_ops phys_vm_ops = {
    .destroy_obj = phys_destroy,
    .get_page = phys_get_page,
};

struct vm_obj* phys_create(uintptr_t phys_addr, size_t npages) {
    ASSERT(phys_addr % PAGE_SIZE == 0);
    size_t start = phys_addr >> PAGE_SHIFT;
    size_t end = start + npages;
    if (end <= start)
        return ERR_PTR(-EOVERFLOW);

    struct phys* phys = slab_cache_alloc(&phys_cache);
    if (IS_ERR(phys))
        return ERR_CAST(phys);
    *phys = (struct phys){
        .vm_obj =
            {
                .vm_ops = &phys_vm_ops,
                .ref_count = 1,
            },
        .start = start,
        .end = end,
    };
    return &phys->vm_obj;
}

void* phys_map(uintptr_t phys_addr, size_t size, unsigned vm_flags) {
    uintptr_t aligned_addr = ROUND_DOWN(phys_addr, PAGE_SIZE);
    size_t npages = DIV_CEIL(phys_addr - aligned_addr + size, PAGE_SIZE);

    struct vm_obj* phys = phys_create(aligned_addr, npages);
    if (IS_ERR(phys))
        return ERR_CAST(phys);

    unsigned char* addr = vm_obj_map(phys, 0, npages, vm_flags | VM_SHARED);
    if (IS_ERR(addr)) {
        vm_obj_unref(phys);
        return addr;
    }
    return addr + (phys_addr - aligned_addr);
}

void phys_unmap(void* virt_addr) { vm_obj_unmap(virt_addr); }

void vm_obj_init(void) {
    slab_cache_init(&anon_cache, sizeof(struct anon));
    slab_cache_init(&phys_cache, sizeof(struct phys));

    zero_page = page_alloc();
    ASSERT_OK(zero_page);
    page_fill(zero_page, 0, 0, PAGE_SIZE);
}
