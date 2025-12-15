#include "private.h"
#include "vm.h"
#include <kernel/containers/vec.h>
#include <kernel/panic.h>

static struct slab* slabs;

void slab_init(struct slab* slab, const char* name, size_t obj_size) {
    // Ensure that the slab fits in a single page
    ASSERT(sizeof(struct vm_region) + obj_size <= PAGE_SIZE);

    *slab = (struct slab){
        .name = name,
        .obj_size = obj_size,
        .next = slabs,
    };
    slabs = slab;
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

    ssize_t start = vm_find_gap(kernel_vm, 1);
    if (IS_ERR(start)) {
        ret = start;
        goto fail;
    }

    pfn = page_alloc_raw();
    if (IS_ERR(pfn)) {
        ret = pfn;
        goto fail;
    }

    uintptr_t start_addr = (uintptr_t)start << PAGE_SHIFT;
    ret = page_table_map(start_addr, pfn, 1, PTE_WRITE | PTE_GLOBAL);
    if (IS_ERR(ret))
        goto fail;

    struct vm_region* region = (struct vm_region*)start_addr;
    *region = (struct vm_region){
        .vm = kernel_vm,
        .start = start,
        .end = start + 1,
        .flags = VM_READ | VM_WRITE | VM_SHARED,
    };
    vm_insert_region(kernel_vm, region);

    mutex_unlock(&kernel_vm->lock);

    uintptr_t end_addr = start_addr + PAGE_SIZE;
    struct slab_obj* obj =
        (struct slab_obj*)ROUND_UP((uintptr_t)(region + 1), slab->obj_size);
    while ((uintptr_t)obj + slab->obj_size <= end_addr) {
        obj->next = slab->free_list;
        slab->free_list = obj;
        ++slab->total_objs;
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
    ++slab->num_active_objs;
    mutex_unlock(&slab->lock);
    return obj;
}

void slab_free(struct slab* slab, void* obj) {
    if (!obj)
        return;
    mutex_lock(&slab->lock);
    ((struct slab_obj*)obj)->next = slab->free_list;
    slab->free_list = obj;
    --slab->num_active_objs;
    mutex_unlock(&slab->lock);
}

int proc_print_slabinfo(struct file* file, struct vec* vec) {
    (void)file;
    int rc = vec_printf(vec, "# name            "
                             "<active_objs> "
                             "<num_objs> "
                             "<objsize> "
                             "<objperslab> "
                             "<pagesperslab>\n");
    if (IS_ERR(rc))
        return rc;
    for (struct slab* slab = slabs; slab; slab = slab->next) {
        size_t obj_offset = ROUND_UP(sizeof(struct vm_region), slab->obj_size);
        size_t objs_per_slab = (PAGE_SIZE - obj_offset) / slab->obj_size;
        size_t pages_per_slab = 1;
        rc = vec_printf(vec, "%-17s %6u %6u %6u %4u %4u\n", slab->name,
                        slab->num_active_objs, slab->total_objs, slab->obj_size,
                        objs_per_slab, pages_per_slab);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}
