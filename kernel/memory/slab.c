#include "private.h"
#include "vm.h"
#include <kernel/panic.h>

void slab_init(struct slab* slab, size_t obj_size) {
    // Ensure that the slab fits in a single page
    ASSERT(sizeof(struct vm_region) + obj_size <= PAGE_SIZE);

    *slab = (struct slab){
        .obj_size = obj_size,
    };
}

struct slab_obj {
    struct slab_obj* next;
};

NODISCARD static int ensure_cache(struct slab* slab) {
    if (slab->free_list)
        return 0;

    int ret = 0;
    ssize_t pfn = -1;
    mutex_lock(&kernel_vm->lock);

    size_t start;
    struct vm_region* prev = vm_find_gap(kernel_vm, 1, &start);
    if (IS_ERR(prev)) {
        ret = PTR_ERR(prev);
        goto fail;
    }

    pfn = page_alloc_raw();
    if (IS_ERR(pfn)) {
        ret = pfn;
        goto fail;
    }

    ret = page_table_map(start << PAGE_SHIFT, pfn, 1, PTE_WRITE | PTE_GLOBAL);
    if (IS_ERR(ret))
        goto fail;

    uintptr_t start_addr = start << PAGE_SHIFT;
    struct vm_region* region = (struct vm_region*)start_addr;
    *region = (struct vm_region){
        .vm = kernel_vm,
        .start = start,
        .end = start + 1,
        .flags = VM_READ | VM_WRITE | VM_SHARED,
    };
    vm_insert_region_after(kernel_vm, prev, region);

    mutex_unlock(&kernel_vm->lock);

    uintptr_t end_addr = start_addr + PAGE_SIZE;
    struct slab_obj* obj =
        (struct slab_obj*)ROUND_UP((uintptr_t)(region + 1), slab->obj_size);
    while ((uintptr_t)obj + slab->obj_size <= end_addr) {
        obj->next = slab->free_list;
        slab->free_list = obj;
        obj = (struct slab_obj*)((uintptr_t)obj + slab->obj_size);
    }

    return 0;

fail:
    if (IS_OK(pfn))
        page_free_raw(pfn);
    mutex_unlock(&kernel_vm->lock);
    return ret;
}

void* slab_alloc(struct slab* slab) {
    mutex_lock(&slab->lock);
    int rc = ensure_cache(slab);
    if (IS_ERR(rc)) {
        mutex_unlock(&slab->lock);
        return ERR_PTR(rc);
    }
    struct slab_obj* obj = slab->free_list;
    slab->free_list = obj->next;
    mutex_unlock(&slab->lock);
    return obj;
}

void slab_free(struct slab* slab, void* obj) {
    if (!obj)
        return;
    mutex_lock(&slab->lock);
    ((struct slab_obj*)obj)->next = slab->free_list;
    slab->free_list = obj;
    mutex_unlock(&slab->lock);
}
