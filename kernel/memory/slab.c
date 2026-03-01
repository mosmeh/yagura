#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/containers/vec.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>

DEFINE_LOCKED(slab, struct slab*, mutex, lock)

static struct slab* slabs;

struct slab_obj {
    struct slab_obj* next;
};

void __slab_init(struct slab* slab, const char* name, size_t obj_alignment,
                 size_t obj_size) {
    obj_alignment = MAX(obj_alignment, _Alignof(struct slab_obj));
    ASSERT(PAGE_SIZE % obj_alignment == 0);

    // Ensure that the object size is large enough to hold slab metadata
    ASSERT(obj_size >= sizeof(struct slab_obj));

    size_t objs_per_slab = 0;
    for (size_t offset = ROUND_UP(sizeof(struct vm_region), obj_alignment);
         offset + obj_size <= PAGE_SIZE;
         offset = ROUND_UP(offset + obj_size, obj_alignment))
        ++objs_per_slab;
    ASSERT(objs_per_slab > 0);

    *slab = (struct slab){
        .name = name,
        .obj_size = obj_size,
        .obj_alignment = obj_alignment,
        .objs_per_slab = objs_per_slab,
        .next = slabs,
    };
    slabs = slab;
}

NODISCARD static int ensure_cache(struct slab* slab) {
    if (slab->free_list)
        return 0;

    uintptr_t start_addr;
    uintptr_t body_addr;
    {
        ssize_t start = vm_find_gap(kernel_vm, 1);
        if (IS_ERR(start))
            return start;

        struct page* page = page_alloc();
        if (IS_ERR(page))
            return PTR_ERR(page);

        start_addr = (uintptr_t)start << PAGE_SHIFT;
        int ret = pagemap_map(kernel_pagemap, start_addr, page_to_pfn(page), 1,
                              VM_WRITE);
        if (IS_ERR(ret)) {
            page_unref(page);
            return ret;
        }

        STATIC_ASSERT(PAGE_SIZE % _Alignof(struct vm_region) == 0);

        struct vm_region* region = (struct vm_region*)start_addr;
        *region = (struct vm_region){
            .vm = kernel_vm,
            .start = start,
            .end = start + 1,
            .flags = VM_READ | VM_WRITE | VM_SHARED,
        };
        vm_insert_region(kernel_vm, region);

        body_addr = (uintptr_t)(region + 1);
    }

    uintptr_t end_addr = start_addr + PAGE_SIZE;
    struct slab_obj* obj = (void*)ROUND_UP(body_addr, slab->obj_alignment);
    while ((uintptr_t)obj + slab->obj_size <= end_addr) {
        obj->next = slab->free_list;
        slab->free_list = obj;
        ++slab->total_objs;
        obj = (void*)(ROUND_UP((uintptr_t)obj + slab->obj_size,
                               slab->obj_alignment));
    }

    return 0;
}

void* slab_alloc(struct slab* slab) {
    for (;;) {
        {
            SCOPED_LOCK(slab, slab);
            if (slab->free_list) {
                struct slab_obj* obj = slab->free_list;
                slab->free_list = obj->next;
                ++slab->num_active_objs;
                return obj;
            }
        }
        SCOPED_LOCK(vm, kernel_vm);
        SCOPED_LOCK(slab, slab);
        int rc = ensure_cache(slab);
        if (IS_ERR(rc))
            return ERR_PTR(rc);
    }
}

void slab_free(struct slab* slab, void* obj) {
    if (!obj)
        return;
    memset(obj, 0xfe, slab->obj_size); // Poison the freed object
    SCOPED_LOCK(slab, slab);
    *(struct slab_obj*)obj = (struct slab_obj){.next = slab->free_list};
    slab->free_list = obj;
    --slab->num_active_objs;
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
        size_t pages_per_slab = 1;
        rc = vec_printf(vec, "%-17s %6zu %6zu %6zu %4zu %4zu\n", slab->name,
                        slab->num_active_objs, slab->total_objs, slab->obj_size,
                        slab->objs_per_slab, pages_per_slab);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}
