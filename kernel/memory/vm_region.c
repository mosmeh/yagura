#include "private.h"
#include <kernel/memory/vm.h>
#include <kernel/task/task.h>

static struct slab region_slab;

void vm_region_init(void) {
    slab_init(&region_slab, "vm_region", sizeof(struct vm_region));
}

struct vm_region* vm_region_create(struct vm* vm, size_t start, size_t end) {
    struct vm_region* region = slab_alloc(&region_slab);
    if (IS_ERR(ASSERT(region)))
        return region;

    *region = (struct vm_region){
        .vm = vm,
        .start = start,
        .end = end,
    };

    return region;
}

void vm_region_destroy(struct vm_region* region) {
    struct vm_obj* obj = region->obj;
    if (obj) {
        if (region->flags & VM_SHARED)
            vm_region_unset_obj(region);
        vm_obj_unref(obj);
    }
    if (region->flags & VM_SHARED)
        ASSERT(tree_is_empty(&region->private_pages));
    pages_clear(&region->private_pages);
    slab_free(&region_slab, region);
}

struct vm_region* vm_region_clone(struct vm* new_vm,
                                  const struct vm_region* region) {
    struct vm_region* cloned = slab_alloc(&region_slab);
    if (IS_ERR(ASSERT(cloned)))
        return cloned;

    *cloned = (struct vm_region){
        .vm = new_vm,
        .start = region->start,
        .end = region->end,
        .flags = region->flags,
    };

    for (struct page* page = pages_first(&region->private_pages); page;
         page = pages_next(page)) {
        struct page* new_page =
            pages_alloc_at(&cloned->private_pages, page->index);
        if (IS_ERR(ASSERT(new_page))) {
            vm_region_destroy(cloned);
            return ERR_CAST(new_page);
        }
        page_copy(new_page, page);
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
    ASSERT(obj);

    region->offset = offset;

    SCOPED_LOCK(vm_obj, obj);
    region->obj = vm_obj_ref(obj);
    if (region->flags & VM_SHARED) {
        region->shared_next = obj->shared_regions;
        obj->shared_regions = region;
    }
}

void vm_region_unset_obj(struct vm_region* region) {
    struct vm_obj* obj = region->obj;
    SCOPED_LOCK(vm_obj, obj);
    struct vm_region* prev = NULL;
    struct vm_region* it = obj->shared_regions;
    for (; it; it = it->shared_next) {
        ASSERT(it->obj == obj);
        if (it == region)
            break;
        prev = it;
    }
    ASSERT(it);
    if (prev) {
        prev->shared_next = region->shared_next;
    } else {
        ASSERT(obj->shared_regions == region);
        obj->shared_regions = region->shared_next;
    }
    region->shared_next = NULL;
}

struct page* vm_region_get_page(struct vm_region* region, size_t index,
                                bool write) {
    if (write && !(region->flags & VM_WRITE))
        return ERR_PTR(-EFAULT);

    struct vm_obj* obj = region->obj;
    if (!obj)
        return ERR_PTR(-EFAULT);

    struct tree_node** new_node = &region->private_pages.root;
    struct tree_node* parent = NULL;
    if (!(region->flags & VM_SHARED)) {
        while (*new_node) {
            parent = *new_node;
            struct page* page = CONTAINER_OF(parent, struct page, tree_node);
            if (index < page->index)
                new_node = &parent->left;
            else if (index > page->index)
                new_node = &parent->right;
            else
                return page;
        }
    }

    const struct vm_ops* vm_ops = obj->vm_ops;
    ASSERT(vm_ops);

    SCOPED_LOCK(vm_obj, obj);

    ASSERT(vm_ops->get_page);
    struct page* shared_page =
        vm_ops->get_page(obj, region->offset + index, write);
    if (IS_ERR(ASSERT(shared_page)))
        return shared_page;

    if (!write || (region->flags & VM_SHARED))
        return shared_page;

    // Copy on write
    struct page* private_page = page_alloc();
    if (IS_ERR(ASSERT(private_page)))
        return private_page;
    private_page->index = index;
    *new_node = &private_page->tree_node;
    tree_insert(&region->private_pages, parent, *new_node);

    page_copy(private_page, shared_page);

    return private_page;
}

void* vm_region_to_virt(const struct vm_region* region) {
    return (void*)(region->start << PAGE_SHIFT);
}

int vm_region_resize(struct vm_region* region, size_t new_npages) {
    struct vm* vm = region->vm;
    ASSERT(vm_is_locked_by_current(vm));

    if (region->obj)
        ASSERT(vm == kernel_vm || vm == current->vm);

    if (new_npages == 0)
        return -EINVAL;

    size_t old_npages = region->end - region->start;
    if (old_npages == new_npages)
        return 0;

    size_t new_end = region->start + new_npages;
    if (new_end <= region->start)
        return -EOVERFLOW;

    // Shrink the region
    if (new_npages < old_npages) {
        if (region->obj)
            page_table_unmap(new_end << PAGE_SHIFT, old_npages - new_npages);
        region->end = new_end;
        return 0;
    }

    // If there is enough space after the region, we can simply extend the
    // region
    struct vm_region* next_region = vm_next_region(region);
    size_t next_start = next_region ? next_region->start : vm->end;
    if (new_end <= next_start) {
        region->end = new_end;
        return 0;
    }

    // Otherwise, we need to allocate a new range
    ssize_t new_start = vm_find_gap(vm, new_npages);
    if (IS_ERR(new_start))
        return new_start;

    // Unmap the old range
    if (region->obj)
        page_table_unmap(region->start << PAGE_SHIFT, old_npages);
    vm_remove_region(region);

    region->start = new_start;
    region->end = new_start + new_npages;
    vm_insert_region(vm, region);

    return 0;
}

int vm_region_set_flags(struct vm_region* region, size_t offset, size_t npages,
                        unsigned flags, unsigned mask) {
    ASSERT(!(flags & ~mask));

    struct vm* vm = region->vm;
    ASSERT(vm_is_locked_by_current(vm));

    if (region->obj)
        ASSERT(vm == kernel_vm || vm == current->vm);

    if (npages == 0)
        return -EINVAL;
    if ((flags & VM_WRITE) && !(flags & VM_READ)) {
        // Write-only mapping is not possible with x86 paging
        return -EINVAL;
    }

    size_t start = region->start + offset;
    size_t end = start + npages;
    if (start < region->start || end <= start)
        return -EOVERFLOW;
    if (region->end < end)
        return -EINVAL;

    unsigned new_flags = (region->flags & ~mask) | flags;
    if (region->flags == new_flags)
        return 0;
    if (region->obj && (region->flags & VM_SHARED) != (new_flags & VM_SHARED))
        return -EINVAL;

    if (offset == 0 && end == region->end) {
        // Modify the whole region
        region->flags = new_flags;
    } else if (offset == 0) {
        // Split the region into two.
        // Left (`region`): [start, end) with new flags
        // Right (`right_region`): [end, region->end) with old flags

        struct vm_region* right_region = slab_alloc(&region_slab);
        if (IS_ERR(ASSERT(right_region)))
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
        region->end = end;
        region->flags = new_flags;

        vm_insert_region(vm, right_region);

        if (region->obj)
            vm_region_set_obj(right_region, region->obj,
                              region->offset + npages);
    } else if (end == region->end) {
        // Split the region into two.
        // Left (`region`): [region->start, start) with old flags
        // Right (`right_region`): [start, end) with new flags

        struct vm_region* right_region = slab_alloc(&region_slab);
        if (IS_ERR(ASSERT(right_region)))
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
        region->end = start;

        vm_insert_region(vm, right_region);

        if (region->obj)
            vm_region_set_obj(right_region, region->obj,
                              region->offset + offset);
    } else {
        // Split the region into three.
        // Left (`region`): [region->start, start) with old flags
        // Middle (`middle_region`): [start, end) with new flags
        // Right (`right_region`): [end, region->end) with old flags

        struct vm_region* middle_region = slab_alloc(&region_slab);
        if (IS_ERR(ASSERT(middle_region)))
            return PTR_ERR(middle_region);
        struct vm_region* right_region = slab_alloc(&region_slab);
        if (IS_ERR(ASSERT(right_region))) {
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
        region->end = start;

        vm_insert_region(vm, middle_region);
        vm_insert_region(vm, right_region);

        if (region->obj) {
            vm_region_set_obj(middle_region, region->obj,
                              region->offset + offset);
            vm_region_set_obj(right_region, region->obj,
                              region->offset + offset + npages);
        }
    }

    if (region->obj)
        page_table_unmap(start << PAGE_SHIFT, npages);

    return 0;
}

int vm_region_free(struct vm_region* region, size_t offset, size_t npages) {
    struct vm* vm = region->vm;
    ASSERT(vm_is_locked_by_current(vm));

    if (region->obj)
        ASSERT(vm == kernel_vm || vm == current->vm);

    if (npages == 0)
        return -EINVAL;

    size_t start = region->start + offset;
    size_t end = start + npages;
    if (start < region->start || end <= start)
        return -EOVERFLOW;
    if (region->end < end)
        return -EINVAL;

    if (region->start == start && region->end == end) {
        // Unmap the whole region
        vm_remove_region(region);
        vm_region_destroy(region);
    } else if (region->start == start) {
        // Unmap the beginning of the region.
        // The region is shrunk to [start, region->end)
        region->start += npages;
        region->offset += npages;

        struct tree pages = {0};
        pages_split_off(&region->private_pages, &pages, npages);
        pages_clear(&region->private_pages);
        region->private_pages = pages;
    } else if (region->end == end) {
        // Unmap the end of the region.
        // The region is shrunk to [region->start, start)
        region->end -= npages;

        pages_truncate(&region->private_pages, offset);
    } else {
        // Split the region into two, unmapping the middle part.
        // Left (`region`): [region->start, start)
        // Right (`right_region`): [end, region->end)

        struct vm_region* right_region = slab_alloc(&region_slab);
        if (IS_ERR(ASSERT(right_region)))
            return PTR_ERR(right_region);

        struct tree middle_pages = {0};
        pages_split_off(&region->private_pages, &middle_pages, offset);
        struct tree right_pages = {0};
        pages_split_off(&middle_pages, &right_pages, npages);
        pages_clear(&middle_pages);

        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .flags = region->flags,
            .private_pages = right_pages,
        };
        region->end = start;

        vm_insert_region(vm, right_region);

        if (region->obj)
            vm_region_set_obj(right_region, region->obj,
                              region->offset + offset + npages);
    }

    if (region->obj)
        page_table_unmap(start << PAGE_SHIFT, npages);

    return 0;
}

int vm_region_invalidate(const struct vm_region* region, size_t offset,
                         size_t npages) {
    struct vm* vm = region->vm;
    ASSERT(vm_is_locked_by_current(vm));

    if (region->obj)
        ASSERT(vm == kernel_vm || vm == current->vm);

    if (npages == 0)
        return -EINVAL;

    size_t start = region->start + offset;
    size_t end = start + npages;
    if (start < region->start || end <= start)
        return -EOVERFLOW;
    if (region->end < end)
        return -EINVAL;

    if (region->obj)
        page_table_unmap(start << PAGE_SHIFT, npages);

    return 0;
}
