#include "private.h"
#include <kernel/interrupts/interrupts.h>
#include <kernel/memory/vm.h>
#include <kernel/task.h>

struct vm* kernel_vm;
static struct slab vm_slab;

void vm_init(void) {
    static struct vm vm;
    kernel_vm = &vm;

    size_t start = DIV_CEIL(KERNEL_VM_START, PAGE_SIZE);
    size_t end = KERNEL_VM_END >> PAGE_SHIFT;
    ASSERT(start < end);
    *kernel_vm = (struct vm){
        .start = start,
        .end = end,
        .page_directory = kernel_page_directory,
        .refcount = REFCOUNT_INIT_ONE,
    };
    current->vm = kernel_vm;

    slab_init(&vm_slab, "vm", sizeof(struct vm));
}

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

struct vm* vm_enter(struct vm* vm) {
    if (vm == current->vm)
        return vm;
    // current->vm needs to be updated BEFORE page_directory_switch().
    // Otherwise, when we are preempted between the two lines,
    // current->vm->page_directory will get out of sync with the actual
    // active page directory.
    struct vm* prev_vm = atomic_exchange(&current->vm, vm);
    page_directory_switch(vm->page_directory);
    return prev_vm;
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

static struct vm* virt_addr_to_vm(void* virt_addr) {
    if (current && vm_contains(current->vm, virt_addr))
        return current->vm;
    if (vm_contains(kernel_vm, virt_addr))
        return kernel_vm;
    return NULL;
}

NODISCARD static int map_page(struct vm* vm, void* virt_addr, bool write) {
    ASSERT(mutex_is_locked_by_current(&vm->lock));

    struct vm_region* region = vm_find(vm, virt_addr);
    if (!region)
        return -EFAULT;
    if (write) {
        if (!(region->flags & VM_WRITE))
            return -EFAULT;
    } else if (!(region->flags & VM_READ))
        return -EFAULT;

    struct vm_obj* obj = region->obj;
    if (!obj)
        return -EFAULT;

    size_t index = ((uintptr_t)virt_addr >> PAGE_SHIFT) - region->start;
    struct page* page = vm_region_get_page(region, index, write);
    if (IS_ERR(page))
        return PTR_ERR(page);

    uintptr_t page_addr = ROUND_DOWN((uintptr_t)virt_addr, PAGE_SIZE);
    uint16_t pte_flags = vm_flags_to_pte_flags(region->flags | obj->flags);
    if (!write)
        pte_flags &= ~PTE_WRITE; // Trigger a page fault on the next write
    return page_table_map(page_addr, page_to_pfn(page), 1, pte_flags);
}

bool vm_handle_page_fault(void* virt_addr, uint32_t error_code) {
    struct vm* vm = virt_addr_to_vm(virt_addr);
    if (!vm)
        return false;

    if (vm == kernel_vm) {
        if (error_code & X86_PF_USER)
            return -EFAULT;
    } else if (error_code & X86_PF_INSTR) {
        // Kernel mode should not execute user-space code
        ASSERT(error_code & X86_PF_USER);
    }

    bool int_flag = push_sti();
    mutex_lock(&vm->lock);
    int rc = map_page(vm, virt_addr, error_code & X86_PF_WRITE);
    mutex_unlock(&vm->lock);
    pop_sti(int_flag);

    return IS_OK(rc);
}

int vm_populate(void* virt_start_addr, void* virt_end_addr, bool write) {
    uintptr_t start = ROUND_DOWN((uintptr_t)virt_start_addr, PAGE_SIZE);
    uintptr_t end = ROUND_UP((uintptr_t)virt_end_addr, PAGE_SIZE);
    if (start >= end)
        return -EINVAL;

    int rc = 0;
    struct vm* prev_vm = NULL;
    for (uintptr_t addr = start; addr < end; addr += PAGE_SIZE) {
        struct vm* vm = virt_addr_to_vm((void*)addr);
        if (!vm) {
            rc = -EFAULT;
            break;
        }
        if (vm != prev_vm) {
            if (prev_vm)
                mutex_unlock(&prev_vm->lock);
            mutex_lock(&vm->lock);
            prev_vm = vm;
        }
        rc = map_page(vm, (void*)addr, write);
        if (IS_ERR(rc))
            break;
    }
    if (prev_vm)
        mutex_unlock(&prev_vm->lock);

    return rc;
}

struct page* vm_get_page(struct vm* vm, void* virt_addr) {
    // If vm is not locked, the returned page may become invalid anytime.
    ASSERT(mutex_is_locked_by_current(&vm->lock));

    struct vm_region* region = vm_find(vm, virt_addr);
    if (!region)
        return NULL;

    size_t index = ((uintptr_t)virt_addr >> PAGE_SHIFT) - region->start;
    return vm_region_get_page(region, index, region->flags & VM_WRITE);
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

// Returns the start address (in pages) of the gap.
// If out_prev_region is not NULL, *out_prev_region is set to the region
// before the gap (or NULL if the gap is at the beginning of the address space).
static ssize_t find_gap(const struct vm* vm, size_t npages,
                        struct vm_region** out_prev_region) {
    // Keep the first page as a guard page.
    // Note that a region can still be allocated at the first page if
    // explicitly requested with vm_alloc_at().
    size_t min_start = MAX(vm->start, 1);
    struct vm_region* first_region = vm_first_region(vm);
    if (!first_region || min_start + npages <= first_region->start) {
        if (out_prev_region)
            *out_prev_region = NULL;
        return min_start;
    }
    struct vm_region* prev = NULL;
    for (struct vm_region* it = first_region; it; it = vm_next_region(it)) {
        ASSERT(it->start < it->end);
        if (prev && prev->end + npages <= it->start) {
            if (out_prev_region)
                *out_prev_region = prev;
            return prev->end;
        }
        prev = it;
    }
    if (prev && prev->end + npages <= vm->end) {
        if (out_prev_region)
            *out_prev_region = prev;
        return prev->end;
    }
    return -ENOMEM;
}

ssize_t vm_find_gap(struct vm* vm, size_t npages) {
    ASSERT(mutex_is_locked_by_current(&vm->lock));

    if (npages == 0)
        return -EINVAL;
    if (vm->start + npages <= vm->start)
        return -EOVERFLOW;
    if (vm->start + npages > vm->end)
        return -ENOMEM;

    if (vm->cached_gap_size >= npages) {
        size_t start = vm->cached_gap_start;
        size_t end = start + npages;
        // The cache might be stale. Verify it.
        struct vm_region* region = find_intersection(vm, start, end);
        ASSERT_OK(region);
        if (!region) {
            vm->cached_gap_start = start + npages;
            vm->cached_gap_size -= npages;
            return start;
        }
        // The cache is stale. Invalidate it and fall back to the full search.
        vm->cached_gap_size = 0;
    }

    struct vm_region* prev_region;
    ssize_t start = find_gap(vm, npages, &prev_region);
    if (IS_ERR(start)) {
        // Invalidate the cache
        vm->cached_gap_size = 0;
        return start;
    }
    size_t gap_start = start + npages;
    struct vm_region* next_region =
        prev_region ? vm_next_region(prev_region) : vm_first_region(vm);
    size_t gap_end = next_region ? next_region->start : vm->end;
    size_t gap_size = gap_end - gap_start;
    if (gap_size >= vm->cached_gap_size) {
        vm->cached_gap_start = gap_start;
        vm->cached_gap_size = gap_size;
    }

    return start;
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

void vm_remove_region(struct vm_region* region) {
    struct vm* vm = region->vm;
    ASSERT(mutex_is_locked_by_current(&vm->lock));
    tree_remove(&vm->regions, &region->tree_node);
}

struct vm_region* vm_alloc(struct vm* vm, size_t npages) {
    ASSERT(mutex_is_locked_by_current(&vm->lock));

    if (npages == 0)
        return ERR_PTR(-EINVAL);

    // slab_alloc() can allocate a new region, so it should be called
    // before vm_find_gap().
    struct vm_region* region = vm_region_create(vm, 0, 0);
    if (IS_ERR(ASSERT(region)))
        return region;

    ssize_t start = vm_find_gap(vm, npages);
    if (IS_ERR(start)) {
        vm_region_destroy(region);
        return ERR_PTR(start);
    }

    region->start = start;
    region->end = start + npages;
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

    struct vm_region* new_region = vm_region_create(vm, start, end);
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
            vm_region_destroy(region);
            return ERR_CAST(rc);
        }
        region = prev;
    }

    vm_insert_region(vm, new_region);

    return new_region;
}
