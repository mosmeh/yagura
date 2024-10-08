#include "memory.h"
#include "private.h"
#include <kernel/panic.h>

void slab_cache_init(struct slab_cache* cache, size_t obj_size) {
    // Ensure that the slab fits in a single page
    ASSERT(sizeof(struct vm_region) + obj_size <= PAGE_SIZE);

    *cache = (struct slab_cache){
        .obj_size = obj_size,
    };
}

struct slab_obj {
    struct slab_obj* next;
};

static int ensure_cache(struct slab_cache* cache) {
    if (cache->free_list)
        return 0;

    int ret = 0;
    spinlock_lock(&kernel_vm->lock);

    size_t start;
    struct vm_region* cursor = vm_find_gap(kernel_vm, PAGE_SIZE, &start);
    if (IS_ERR(cursor)) {
        ret = PTR_ERR(cursor);
        goto fail;
    }

    size_t phys_index = page_alloc_raw();
    if (!phys_index) {
        ret = -ENOMEM;
        goto fail;
    }

    ret = page_table_map(start, phys_index, 1, PTE_WRITE | PTE_GLOBAL);
    if (IS_ERR(ret))
        goto fail;

    struct vm_region* region = (struct vm_region*)(start * PAGE_SIZE);
    *region = (struct vm_region){
        .start = start,
        .end = start + 1,
        .flags = VM_READ | VM_WRITE,
    };
    vm_insert_region_after(kernel_vm, cursor, region);

    spinlock_unlock(&kernel_vm->lock);

    struct slab_obj* obj = (struct slab_obj*)(region + 1);
    for (size_t i = 0; i < PAGE_SIZE / cache->obj_size - 1; ++i) {
        obj->next = cache->free_list;
        cache->free_list = obj;
        obj = (struct slab_obj*)((uintptr_t)obj + cache->obj_size);
    }

    return 0;

fail:
    spinlock_unlock(&kernel_vm->lock);
    return ret;
}

void* slab_cache_alloc(struct slab_cache* cache) {
    mutex_lock(&cache->lock);
    int rc = ensure_cache(cache);
    if (IS_ERR(rc)) {
        mutex_unlock(&cache->lock);
        return ERR_PTR(rc);
    }
    struct slab_obj* obj = cache->free_list;
    cache->free_list = obj->next;
    mutex_unlock(&cache->lock);
    return obj;
}

void slab_cache_free(struct slab_cache* cache, void* obj) {
    if (!obj)
        return;
    mutex_lock(&cache->lock);
    ((struct slab_obj*)obj)->next = cache->free_list;
    cache->free_list = obj;
    mutex_unlock(&cache->lock);
}
