#include "vm.h"
#include "private.h"
#include <common/string.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/panic.h>
#include <kernel/task.h>

static struct slab vm_slab;

struct vm* vm_create(void* start, void* end) {
    if (end <= start || KERNEL_VM_END <= (uintptr_t)start)
        return ERR_PTR(-EINVAL);
    struct vm* vm = slab_alloc(&vm_slab);
    if (IS_ERR(ASSERT(vm)))
        return vm;
    struct page_directory* page_directory = page_directory_create();
    if (IS_ERR(ASSERT(page_directory))) {
        slab_free(&vm_slab, vm);
        return ERR_CAST(page_directory);
    }
    *vm = (struct vm){
        .start = DIV_CEIL((uintptr_t)start, PAGE_SIZE),
        .end = (uintptr_t)end >> PAGE_SHIFT,
        .page_directory = page_directory,
        .refcount = REFCOUNT_INIT_ONE,
    };
    return vm;
}

struct vm* vm_ref(struct vm* vm) {
    ASSERT(vm);
    ASSERT(vm != kernel_vm);
    refcount_inc(&vm->refcount);
    return vm;
}

void vm_region_set_obj(struct vm_region* region, struct vm_obj* obj,
                       size_t offset) {
    ASSERT(mutex_is_locked_by_current(&region->vm->lock));
    ASSERT(!region->obj);
    ASSERT(!region->shared_next);
    ASSERT(obj);

    region->offset = offset;

    mutex_lock(&obj->lock);
    region->obj = vm_obj_ref(obj);
    if (region->flags & VM_SHARED) {
        region->shared_next = obj->shared_regions;
        obj->shared_regions = region;
    }
    mutex_unlock(&obj->lock);
}

static void vm_region_unset_obj(struct vm_region* region) {
    struct vm_obj* obj = region->obj;
    mutex_lock(&obj->lock);
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
    mutex_unlock(&obj->lock);
}

static struct slab region_slab;

static void vm_region_destroy(struct vm_region* region) {
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

void vm_unref(struct vm* vm) {
    if (!vm)
        return;
    ASSERT(vm != kernel_vm);
    if (refcount_dec(&vm->refcount))
        return;

    ASSERT(vm != current->vm);

    for (;;) {
        struct tree_node* node = vm->regions.root;
        if (!node)
            break;
        tree_remove(&vm->regions, node);
        struct vm_region* region =
            CONTAINER_OF(node, struct vm_region, tree_node);
        vm_region_destroy(region);
    }

    page_directory_destroy(vm->page_directory);
    slab_free(&vm_slab, vm);
}

struct vm* vm_get_current(void) { return current ? current->vm : kernel_vm; }

struct vm* vm_enter(struct vm* vm) {
    if (vm == vm_get_current())
        return vm;
    ASSERT(current);
    // current->vm needs to be updated BEFORE page_directory_switch().
    // Otherwise, when we are preempted between the two lines,
    // current->vm->page_directory will get out of sync with the actual
    // active page directory.
    struct vm* prev_vm = atomic_exchange(&current->vm, vm);
    page_directory_switch(vm->page_directory);
    return prev_vm;
}

static struct vm_region* vm_region_clone(struct vm* new_vm,
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

struct vm* vm_clone(struct vm* vm) {
    ASSERT(vm != kernel_vm);

    struct vm* new_vm = slab_alloc(&vm_slab);
    if (IS_ERR(ASSERT(new_vm)))
        return new_vm;

    *new_vm = (struct vm){
        .start = vm->start,
        .end = vm->end,
        .refcount = REFCOUNT_INIT_ONE,
    };

    mutex_lock(&new_vm->lock);
    mutex_lock(&vm->lock);
    int ret = 0;

    struct page_directory* page_directory = page_directory_create();
    if (IS_ERR(ASSERT(page_directory))) {
        ret = PTR_ERR(page_directory);
        goto fail;
    }
    new_vm->page_directory = page_directory;

    for (const struct vm_region* it = vm_first_region(vm); it;
         it = vm_next_region(it)) {
        struct vm_region* new_region = vm_region_clone(new_vm, it);
        if (IS_ERR(ASSERT(new_region))) {
            ret = PTR_ERR(new_region);
            goto fail;
        }

        struct tree_node** new_node = &new_vm->regions.root;
        struct tree_node* parent = NULL;
        while (*new_node) {
            parent = *new_node;
            struct vm_region* region =
                CONTAINER_OF(parent, struct vm_region, tree_node);
            if (new_region->start < region->start)
                new_node = &parent->left;
            else if (new_region->start > region->start)
                new_node = &parent->right;
            else
                UNREACHABLE();
        }
        *new_node = &new_region->tree_node;
        tree_insert(&new_vm->regions, parent, *new_node);
    }

fail:
    mutex_unlock(&vm->lock);
    mutex_unlock(&new_vm->lock);
    if (IS_ERR(ret)) {
        vm_unref(new_vm);
        return ERR_PTR(ret);
    }
    return new_vm;
}

static bool vm_contains(const struct vm* vm, void* virt_addr) {
    size_t index = (uintptr_t)virt_addr >> PAGE_SHIFT;
    return vm->start <= index && index < vm->end;
}

static struct page* vm_region_handle_page_fault(struct vm_region* region,
                                                size_t index,
                                                uint32_t error_code) {
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

    int ret = 0;
    mutex_lock(&obj->lock);

    ASSERT(vm_ops->get_page);
    struct page* shared_page = vm_ops->get_page(obj, region->offset + index,
                                                error_code & X86_PF_WRITE);
    if (IS_ERR(ASSERT(shared_page))) {
        ret = PTR_ERR(shared_page);
        goto fail;
    }
    ASSERT(shared_page);

    if (!(error_code & X86_PF_WRITE) || (region->flags & VM_SHARED)) {
        mutex_unlock(&obj->lock);
        return shared_page;
    }

    // Copy on write
    struct page* private_page = page_alloc();
    if (IS_ERR(ASSERT(private_page))) {
        ret = PTR_ERR(private_page);
        goto fail;
    }
    private_page->index = index;
    *new_node = &private_page->tree_node;
    tree_insert(&region->private_pages, parent, *new_node);

    page_copy(private_page, shared_page);

    mutex_unlock(&obj->lock);
    return private_page;

fail:
    mutex_unlock(&obj->lock);
    return ERR_PTR(ret);
}

NODISCARD static int do_handle_page_fault(void* virt_addr,
                                          uint32_t error_code) {
    struct vm* vm;
    if (current && vm_contains(current->vm, virt_addr))
        vm = current->vm;
    else if (vm_contains(kernel_vm, virt_addr))
        vm = kernel_vm;
    else
        return -ENOMEM;

    if (vm == kernel_vm) {
        if (error_code & X86_PF_USER)
            return false;
    } else if (error_code & X86_PF_INSTR) {
        // Kernel mode should not execute user-space code
        ASSERT(error_code & X86_PF_USER);
    }

    int ret = 0;
    bool int_flag = push_sti();
    mutex_lock(&vm->lock);

    struct vm_region* region = vm_find(vm, virt_addr);
    if (!region) {
        ret = -EFAULT;
        goto fail;
    }
    struct vm_obj* obj = region->obj;
    if (!obj) {
        ret = -EFAULT;
        goto fail;
    }

    if (error_code & X86_PF_WRITE) {
        if (!(region->flags & VM_WRITE)) {
            ret = -EINVAL;
            goto fail;
        }
    } else if (!(region->flags & VM_READ)) {
        ret = -EINVAL;
        goto fail;
    }

    size_t index = ((uintptr_t)virt_addr >> PAGE_SHIFT) - region->start;
    struct page* page = vm_region_handle_page_fault(region, index, error_code);
    if (IS_ERR(ASSERT(page))) {
        ret = PTR_ERR(page);
        goto fail;
    }

    uintptr_t page_addr = ROUND_DOWN((uintptr_t)virt_addr, PAGE_SIZE);
    uint16_t pte_flags = vm_flags_to_pte_flags(region->flags | obj->flags);
    if (!(error_code & X86_PF_WRITE))
        pte_flags &= ~PTE_WRITE; // Trigger a page fault on the next write
    ret = page_table_map(page_addr, page_to_pfn(page), 1, pte_flags);

fail:
    mutex_unlock(&vm->lock);
    pop_sti(int_flag);
    return ret;
}

bool vm_handle_page_fault(void* virt_addr, uint32_t error_code) {
    return IS_OK(do_handle_page_fault(virt_addr, error_code));
}

int vm_populate(void* virt_start_addr, void* virt_end_addr, bool write) {
    uintptr_t start = ROUND_DOWN((uintptr_t)virt_start_addr, PAGE_SIZE);
    uintptr_t end = ROUND_UP((uintptr_t)virt_end_addr, PAGE_SIZE);
    if (start >= end)
        return -EINVAL;

    uint32_t error_code = write ? X86_PF_WRITE : 0;
    for (uintptr_t addr = start; addr < end; addr += PAGE_SIZE) {
        int rc = do_handle_page_fault((void*)addr, error_code);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

struct vm_region* vm_first_region(const struct vm* vm) {
    struct tree_node* node = tree_first(&vm->regions);
    if (!node)
        return NULL;
    return CONTAINER_OF(node, struct vm_region, tree_node);
}

struct vm_region* vm_next_region(const struct vm_region* region) {
    struct tree_node* node = tree_next(&region->tree_node);
    if (!node)
        return NULL;
    return CONTAINER_OF(node, struct vm_region, tree_node);
}

struct vm_region* vm_prev_region(const struct vm_region* region) {
    struct tree_node* node = tree_prev(&region->tree_node);
    if (!node)
        return NULL;
    return CONTAINER_OF(node, struct vm_region, tree_node);
}

static struct vm_region* find_region_with_upper_bound(const struct vm* vm,
                                                      size_t index) {
    struct tree_node* node = vm->regions.root;
    struct vm_region* result = NULL;
    while (node) {
        struct vm_region* region =
            CONTAINER_OF(node, struct vm_region, tree_node);
        if (index < region->start) {
            node = node->left;
        } else if (index > region->start) {
            result = region;
            node = node->right;
        } else {
            return region;
        }
    }
    return result;
}

struct vm_region* vm_find(const struct vm* vm, void* virt_addr) {
    ASSERT(mutex_is_locked_by_current(&vm->lock));
    if (!vm_contains(vm, virt_addr))
        return NULL;
    size_t index = (uintptr_t)virt_addr >> PAGE_SHIFT;
    struct vm_region* region = find_region_with_upper_bound(vm, index);
    if (!region)
        return NULL;
    ASSERT(region->start <= index);
    if (index < region->end)
        return region;
    return NULL;
}

static struct vm_region* find_intersection(const struct vm* vm, size_t start,
                                           size_t end) {
    if (start >= end)
        return ERR_PTR(-EINVAL);
    if (end <= vm->start || vm->end <= start)
        return NULL;
    struct vm_region* region = find_region_with_upper_bound(vm, end - 1);
    if (!region)
        return NULL;
    ASSERT(region->start < end);
    if (start < region->end)
        return region;
    return NULL;
}

struct vm_region* vm_find_intersection(const struct vm* vm,
                                       void* virt_start_addr,
                                       void* virt_end_addr) {
    ASSERT(mutex_is_locked_by_current(&vm->lock));
    size_t start = (uintptr_t)virt_start_addr >> PAGE_SHIFT;
    size_t end = DIV_CEIL((uintptr_t)virt_end_addr, PAGE_SIZE);
    return find_intersection(vm, start, end);
}

ssize_t vm_find_gap(struct vm* vm, size_t npages) {
    ASSERT(mutex_is_locked_by_current(&vm->lock));

    if (npages == 0)
        return -EINVAL;
    if (vm->start + npages <= vm->start)
        return -EOVERFLOW;
    if (vm->start + npages > vm->end)
        return -ENOMEM;

    // Keep the first page as a guard page.
    // Note that a region can still be allocated at the first page if
    // explicitly requested with vm_alloc_at().
    size_t min_start = MAX(vm->start, 1);
    struct vm_region* first_region = vm_first_region(vm);
    if (!first_region || min_start + npages <= first_region->start)
        return min_start;
    struct vm_region* prev = NULL;
    for (struct vm_region* it = first_region; it; it = vm_next_region(it)) {
        ASSERT(it->start < it->end);
        if (prev && prev->end + npages <= it->start)
            return prev->end;
        prev = it;
    }
    if (prev && prev->end + npages <= vm->end)
        return prev->end;
    return -ENOMEM;
}

void vm_insert_region(struct vm* vm, struct vm_region* new_region) {
    ASSERT(vm == new_region->vm);
    struct tree_node** new_node = &vm->regions.root;
    struct tree_node* parent = NULL;
    while (*new_node) {
        parent = *new_node;
        struct vm_region* region =
            CONTAINER_OF(parent, struct vm_region, tree_node);
        if (new_region->start < region->start)
            new_node = &parent->left;
        else if (new_region->start > region->start)
            new_node = &parent->right;
        else
            UNREACHABLE();
    }
    *new_node = &new_region->tree_node;
    tree_insert(&vm->regions, parent, *new_node);
}

struct vm_region* vm_alloc(struct vm* vm, size_t npages) {
    ASSERT(mutex_is_locked_by_current(&vm->lock));

    if (npages == 0)
        return ERR_PTR(-EINVAL);

    // slab_alloc() can allocate a new region, so it should be called
    // before vm_find_gap().
    struct vm_region* region = slab_alloc(&region_slab);
    if (IS_ERR(ASSERT(region)))
        return region;

    ssize_t start = vm_find_gap(vm, npages);
    if (IS_ERR(start)) {
        slab_free(&region_slab, region);
        return ERR_PTR(start);
    }

    *region = (struct vm_region){
        .vm = vm,
        .start = start,
        .end = start + npages,
    };
    vm_insert_region(vm, region);

    return region;
}

struct vm_region* vm_alloc_at(struct vm* vm, void* virt_addr, size_t npages) {
    ASSERT(mutex_is_locked_by_current(&vm->lock));
    ASSERT((uintptr_t)virt_addr % PAGE_SIZE == 0);

    if (npages == 0)
        return ERR_PTR(-EINVAL);

    size_t start = (uintptr_t)virt_addr >> PAGE_SHIFT;
    size_t end = start + npages;
    if (end <= start)
        return ERR_PTR(-EOVERFLOW);
    if (start < vm->start || vm->end < end)
        return ERR_PTR(-ERANGE);

    struct vm_region* new_region = slab_alloc(&region_slab);
    if (IS_ERR(ASSERT(new_region)))
        return new_region;

    struct vm_region* region = find_intersection(vm, start, end);
    ASSERT_OK(region);

    // Free overlapping regions
    while (region && start < region->end) {
        struct vm_region* prev = vm_prev_region(region);
        size_t offset = MAX(start, region->start) - region->start;
        size_t npages = MIN(end, region->end) - region->start - offset;
        int rc = vm_region_free(region, offset, npages);
        if (IS_ERR(rc)) {
            // The only case it fails is when the region encompasses
            // [start, end) and the region gets split into two regions.
            // In this case, it is the only region that overlaps with
            // the new_region, so we don't have to worry about recovering
            // other regions that have been already removed.
            slab_free(&region_slab, new_region);
            return ERR_CAST(rc);
        }
        region = prev;
    }

    *new_region = (struct vm_region){
        .vm = vm,
        .start = start,
        .end = end,
    };
    vm_insert_region(vm, new_region);

    return new_region;
}

void* vm_region_to_virt(const struct vm_region* region) {
    return (void*)(region->start << PAGE_SHIFT);
}

void vm_region_remove(struct vm_region* region) {
    struct vm* vm = region->vm;
    ASSERT(mutex_is_locked_by_current(&vm->lock));
    tree_remove(&vm->regions, &region->tree_node);
}

int vm_region_resize(struct vm_region* region, size_t new_npages) {
    struct vm* vm = region->vm;
    ASSERT(vm == kernel_vm || vm == vm_get_current());
    ASSERT(mutex_is_locked_by_current(&vm->lock));

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
    page_table_unmap(region->start << PAGE_SHIFT, old_npages);
    vm_region_remove(region);

    region->start = new_start;
    region->end = new_start + new_npages;
    vm_insert_region(vm, region);

    return 0;
}

int vm_region_set_flags(struct vm_region* region, size_t offset, size_t npages,
                        unsigned flags, unsigned mask) {
    ASSERT(!(flags & ~mask));

    struct vm* vm = region->vm;
    ASSERT(vm == kernel_vm || vm == vm_get_current());
    ASSERT(mutex_is_locked_by_current(&vm->lock));

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

    page_table_unmap(start << PAGE_SHIFT, npages);

    return 0;
}

int vm_region_free(struct vm_region* region, size_t offset, size_t npages) {
    struct vm* vm = region->vm;
    ASSERT(vm == kernel_vm || vm == vm_get_current());
    ASSERT(mutex_is_locked_by_current(&vm->lock));

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
        vm_region_remove(region);
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

    page_table_unmap(start << PAGE_SHIFT, npages);

    return 0;
}

int vm_region_invalidate(const struct vm_region* region, size_t offset,
                         size_t npages) {
    struct vm* vm = region->vm;
    ASSERT(vm == kernel_vm || vm == vm_get_current());
    ASSERT(mutex_is_locked_by_current(&vm->lock));

    if (npages == 0)
        return -EINVAL;

    size_t start = region->start + offset;
    size_t end = start + npages;
    if (start < region->start || end <= start)
        return -EOVERFLOW;
    if (region->end < end)
        return -EINVAL;

    page_table_unmap(start << PAGE_SHIFT, npages);

    return 0;
}

struct vm* kernel_vm;

void vm_init(void) {
    static struct vm vm;
    kernel_vm = &vm;

    size_t start = DIV_CEIL(KERNEL_VM_START, PAGE_SIZE);
    size_t end = KERNEL_VM_END >> PAGE_SHIFT;
    ASSERT(start < end);
    vm = (struct vm){
        .start = start,
        .end = end,
        .page_directory = kernel_page_directory,
        .refcount = REFCOUNT_INIT_ONE,
    };

    slab_init(&vm_slab, "vm", sizeof(struct vm));
    slab_init(&region_slab, "vm_region", sizeof(struct vm_region));
}
