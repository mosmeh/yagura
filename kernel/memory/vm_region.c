#include "private.h"
#include <kernel/memory/phys.h>
#include <kernel/memory/vm.h>
#include <kernel/task/task.h>

static struct slab region_slab;

void vm_region_init(void) {
    SLAB_INIT_FOR_TYPE(&region_slab, "vm_region", struct vm_region);
}

struct vm_region* vm_region_create(struct vm* vm, size_t start, size_t end) {
    struct vm_region* region = ASSERT(slab_alloc(&region_slab));
    if (IS_ERR(region))
        return region;

    *region = (struct vm_region){
        .vm = vm,
        .start = start,
        .end = end,
    };

    return region;
}

static void vm_region_unset_obj(struct vm_region* region) {
    struct vm_obj* obj FREE(vm_obj) = ASSERT_PTR(region->obj);
    SCOPED_LOCK(vm_obj, obj);

    struct vm_region* prev = NULL;
    struct vm_region* it = obj->shared_regions;
    for (; it; it = it->shared_next) {
        ASSERT(it->obj == obj);
        if (it == region)
            break;
        prev = it;
    }

    region->obj = NULL;

    if (!(region->flags & VM_SHARED)) {
        ASSERT(!it);
        return;
    }

    ASSERT_PTR(it);
    if (prev) {
        prev->shared_next = region->shared_next;
    } else {
        ASSERT(obj->shared_regions == region);
        obj->shared_regions = region->shared_next;
    }
    region->shared_next = NULL;
}

void vm_region_destroy(struct vm_region* region) {
    if (region->obj)
        vm_region_unset_obj(region);
    if (region->flags & VM_SHARED)
        ASSERT(tree_is_empty(&region->private_pages));
    pages_clear(&region->private_pages);
    slab_free(&region_slab, region);
}

struct vm_region* vm_region_clone(struct vm* new_vm,
                                  const struct vm_region* region) {
    struct vm_region* cloned = ASSERT(slab_alloc(&region_slab));
    if (IS_ERR(cloned))
        return cloned;

    *cloned = (struct vm_region){
        .vm = new_vm,
        .start = region->start,
        .end = region->end,
        .flags = region->flags,
    };

    {
        struct page* page FREE(page) = pages_first(&region->private_pages);
        while (page) {
            struct page* new_page FREE(page) =
                ASSERT(pages_alloc_at(&cloned->private_pages, page->index));
            if (IS_ERR(new_page)) {
                vm_region_destroy(cloned);
                return ERR_CAST(new_page);
            }
            page_copy(new_page, page);
            struct page* next_page = pages_next(page);
            page_unref(page);
            page = next_page;
        }
    }

    struct vm_obj* obj = region->obj;
    if (obj)
        vm_region_set_obj(cloned, obj, region->offset);

    return cloned;
}

void vm_region_set_obj(struct vm_region* region, struct vm_obj* obj,
                       size_t offset) {
    ASSERT(vm_is_locked_by_current(region->vm));
    ASSERT(!region->obj);
    ASSERT(!region->shared_next);
    ASSERT_PTR(obj);

    SCOPED_LOCK(vm_obj, obj);
    region->obj = vm_obj_ref(obj);
    region->offset = offset;
    if (region->flags & VM_SHARED) {
        region->shared_next = obj->shared_regions;
        obj->shared_regions = region;
    }
}

void* vm_region_to_virt(const struct vm_region* region) {
    return (void*)(region->start << PAGE_SHIFT);
}

int vm_region_resize(struct vm_region* region, size_t new_npages) {
    struct vm* vm = region->vm;
    ASSERT(vm_is_locked_by_current(vm));

    if (new_npages == 0)
        return -EINVAL;

    size_t old_npages = region->end - region->start;
    if (old_npages == new_npages)
        return 0;

    size_t new_end = region->start + new_npages;
    if (new_end <= region->start)
        return -EOVERFLOW;

    struct vm_obj* obj = region->obj;

    // Shrink the region
    if (new_npages < old_npages) {
        if (obj)
            vm_obj_lock(obj);
        region->end = new_end;
        if (obj) {
            pagemap_unmap(vm->pagemap, new_end << PAGE_SHIFT,
                          old_npages - new_npages);
            vm_obj_unlock(obj);
        }
        return 0;
    }

    // If there is enough space after the region, we can simply extend the
    // region
    struct vm_region* next_region = vm_next_region(region);
    size_t next_start = next_region ? next_region->start : vm->end;
    if (new_end <= next_start) {
        if (obj)
            vm_obj_lock(obj);
        region->end = new_end;
        if (obj)
            vm_obj_unlock(obj);
        return 0;
    }

    // Otherwise, we need to allocate a new range
    ssize_t new_start = vm_find_gap(vm, new_npages);
    if (IS_ERR(new_start))
        return new_start;

    // Unmap the old range
    size_t old_start = region->start;
    if (obj)
        vm_obj_lock(obj);
    vm_remove_region(region);
    region->start = new_start;
    region->end = new_start + new_npages;
    vm_insert_region(vm, region);
    if (obj) {
        pagemap_unmap(vm->pagemap, old_start << PAGE_SHIFT, old_npages);
        vm_obj_unlock(obj);
    }

    return 0;
}

int vm_region_set_flags(struct vm_region* region, size_t offset, size_t npages,
                        unsigned flags, unsigned mask) {
    ASSERT(!(flags & ~mask));

    struct vm* vm = region->vm;
    ASSERT(vm_is_locked_by_current(vm));

    if (npages == 0)
        return -EINVAL;

    size_t start = region->start + offset;
    size_t end = start + npages;
    if (start < region->start || end <= start)
        return -EOVERFLOW;
    if (region->end < end)
        return -EINVAL;

    unsigned new_flags = (region->flags & ~mask) | flags;
    if (region->flags == new_flags)
        return 0;

    struct vm_obj* obj = region->obj;
    if (obj && (region->flags & VM_SHARED) != (new_flags & VM_SHARED))
        return -EINVAL;

    uintptr_t start_addr = start << PAGE_SHIFT;
    if (offset == 0 && end == region->end) {
        // Modify the whole region
        if (obj)
            vm_obj_lock(obj);
        region->flags = new_flags;
        if (obj) {
            pagemap_unmap(vm->pagemap, start_addr, npages);
            vm_obj_unlock(obj);
        }
    } else if (offset == 0) {
        // Split the region into two.
        // Left (`region`): [start, end) with new flags
        // Right (`right_region`): [end, region->end) with old flags

        struct vm_region* right_region = ASSERT(slab_alloc(&region_slab));
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);

        struct tree right_pages = {0};
        pages_split_off(&region->private_pages, &right_pages, npages);
        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .flags = region->flags,
            .private_pages = right_pages,
        };

        if (obj)
            vm_obj_lock(obj);
        region->end = end;
        region->flags = new_flags;
        vm_insert_region(vm, right_region);
        if (obj) {
            vm_region_set_obj(right_region, obj, region->offset + npages);
            pagemap_unmap(vm->pagemap, start_addr, npages);
            vm_obj_unlock(obj);
        }
    } else if (end == region->end) {
        // Split the region into two.
        // Left (`region`): [region->start, start) with old flags
        // Right (`right_region`): [start, end) with new flags

        struct vm_region* right_region = ASSERT(slab_alloc(&region_slab));
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);

        struct tree right_pages = {0};
        pages_split_off(&region->private_pages, &right_pages, offset);

        *right_region = (struct vm_region){
            .vm = vm,
            .start = start,
            .end = end,
            .flags = new_flags,
            .private_pages = right_pages,
        };

        if (obj)
            vm_obj_lock(obj);
        region->end = start;
        vm_insert_region(vm, right_region);
        if (obj) {
            vm_region_set_obj(right_region, obj, region->offset + offset);
            pagemap_unmap(vm->pagemap, start_addr, npages);
            vm_obj_unlock(obj);
        }
    } else {
        // Split the region into three.
        // Left (`region`): [region->start, start) with old flags
        // Middle (`middle_region`): [start, end) with new flags
        // Right (`right_region`): [end, region->end) with old flags

        struct vm_region* middle_region = ASSERT(slab_alloc(&region_slab));
        if (IS_ERR(middle_region))
            return PTR_ERR(middle_region);
        struct vm_region* right_region = ASSERT(slab_alloc(&region_slab));
        if (IS_ERR(right_region)) {
            slab_free(&region_slab, middle_region);
            return PTR_ERR(right_region);
        }

        struct tree middle_pages = {0};
        pages_split_off(&region->private_pages, &middle_pages, offset);
        struct tree right_pages = {0};
        pages_split_off(&middle_pages, &right_pages, npages);

        *middle_region = (struct vm_region){
            .vm = vm,
            .start = start,
            .end = end,
            .flags = new_flags,
            .private_pages = middle_pages,
        };
        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .flags = region->flags,
            .private_pages = right_pages,
        };

        if (obj)
            vm_obj_lock(obj);
        region->end = start;
        vm_insert_region(vm, middle_region);
        vm_insert_region(vm, right_region);
        if (obj) {
            vm_region_set_obj(middle_region, obj, region->offset + offset);
            vm_region_set_obj(right_region, obj,
                              region->offset + offset + npages);
            pagemap_unmap(vm->pagemap, start_addr, npages);
            vm_obj_unlock(obj);
        }
    }

    return 0;
}

int vm_region_free(struct vm_region* region, size_t offset, size_t npages) {
    struct vm* vm = region->vm;
    ASSERT(vm_is_locked_by_current(vm));

    if (npages == 0)
        return -EINVAL;

    size_t start = region->start + offset;
    size_t end = start + npages;
    if (start < region->start || end <= start)
        return -EOVERFLOW;
    if (region->end < end)
        return -EINVAL;

    size_t start_addr = start << PAGE_SHIFT;
    struct vm_obj* obj = region->obj;
    if (region->start == start && region->end == end) {
        // Unmap the whole region
        if (obj) {
            vm_obj_ref(obj);
            vm_obj_lock(obj);
        }
        vm_remove_region(region);
        if (obj) {
            vm_region_unset_obj(region);
            pagemap_unmap(vm->pagemap, start_addr, npages);
            vm_obj_unlock(obj);
            vm_obj_unref(obj);
        }
        vm_region_destroy(region);
    } else if (region->start == start) {
        // Unmap the beginning of the region.
        // The region is shrunk to [start, region->end)

        struct tree pages = {0};
        pages_split_off(&region->private_pages, &pages, npages);
        struct tree freed_pages = region->private_pages;
        region->private_pages = pages;

        if (obj)
            vm_obj_lock(obj);
        region->start += npages;
        region->offset += npages;
        if (obj) {
            pagemap_unmap(vm->pagemap, start_addr, npages);
            vm_obj_unlock(obj);
        }

        pages_clear(&freed_pages);
    } else if (region->end == end) {
        // Unmap the end of the region.
        // The region is shrunk to [region->start, start)

        struct tree freed_pages = {0};
        pages_split_off(&region->private_pages, &freed_pages, offset);

        if (obj)
            vm_obj_lock(obj);
        region->end -= npages;
        if (obj) {
            pagemap_unmap(vm->pagemap, start_addr, npages);
            vm_obj_unlock(obj);
        }

        pages_clear(&freed_pages);
    } else {
        // Split the region into two, unmapping the middle part.
        // Left (`region`): [region->start, start)
        // Right (`right_region`): [end, region->end)

        struct vm_region* right_region = ASSERT(slab_alloc(&region_slab));
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);

        struct tree middle_pages = {0};
        pages_split_off(&region->private_pages, &middle_pages, offset);
        struct tree right_pages = {0};
        pages_split_off(&middle_pages, &right_pages, npages);

        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .flags = region->flags,
            .private_pages = right_pages,
        };

        if (obj)
            vm_obj_lock(obj);
        region->end = start;
        vm_insert_region(vm, right_region);
        if (obj) {
            vm_region_set_obj(right_region, obj,
                              region->offset + offset + npages);
            pagemap_unmap(vm->pagemap, start_addr, npages);
            vm_obj_unlock(obj);
        }

        pages_clear(&middle_pages);
    }

    return 0;
}
