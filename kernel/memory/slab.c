#include "memory.h"
#include "memory_private.h"
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
    mutex_lock(&kernel_vm->lock);

    uintptr_t virt_addr;
    struct vm_region* cursor = vm_find_gap(kernel_vm, PAGE_SIZE, &virt_addr);
    if (IS_ERR(cursor)) {
        ret = PTR_ERR(cursor);
        goto fail;
    }

    ret = page_table_map_anon(virt_addr, PAGE_SIZE, PTE_WRITE | PTE_GLOBAL);
    if (IS_ERR(ret))
        goto fail;

    struct vm_region* region = (struct vm_region*)virt_addr;
    *region = (struct vm_region){
        .start = virt_addr,
        .end = virt_addr + PAGE_SIZE,
        .flags = VM_RW,
    };
    vm_insert_region_after(kernel_vm, cursor, region);

    mutex_unlock(&kernel_vm->lock);

    struct slab_obj* obj =
        (struct slab_obj*)(virt_addr + sizeof(struct vm_region));
    for (size_t i = 0; i < PAGE_SIZE / cache->obj_size - 1; ++i) {
        obj->next = cache->free_list;
        cache->free_list = obj;
        obj = (struct slab_obj*)((uintptr_t)obj + cache->obj_size);
    }

    return 0;

fail:
    mutex_unlock(&kernel_vm->lock);
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
    mutex_lock(&cache->lock);
    ((struct slab_obj*)obj)->next = cache->free_list;
    cache->free_list = obj;
    mutex_unlock(&cache->lock);
}
