#include "private.h"
#include <common/string.h>
#include <kernel/interrupts.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/vm.h>
#include <kernel/task/task.h>

static struct vm __kernel_vm;
struct vm* kernel_vm = &__kernel_vm;
static struct slab vm_slab;

void vm_init(void) {
    size_t start = DIV_CEIL(KERNEL_VM_START, PAGE_SIZE);
    size_t end = KERNEL_VM_END >> PAGE_SHIFT;
    ASSERT(start < end);
    *kernel_vm = (struct vm){
        .start = start,
        .end = end,
        .pagemap = kernel_pagemap,
        .refcount = REFCOUNT_INIT_ONE,
    };
    current->vm = kernel_vm;
    pagemap_switch(kernel_pagemap);

    SLAB_INIT_FOR_TYPE(&vm_slab, "vm", struct vm);
}

struct vm* vm_create(void* start, void* end) {
    if (end <= start)
        return ERR_PTR(-EINVAL);
    struct vm* vm = ASSERT(slab_alloc(&vm_slab));
    if (IS_ERR(vm))
        return vm;
    struct pagemap* pagemap = ASSERT(pagemap_create());
    if (IS_ERR(pagemap)) {
        slab_free(&vm_slab, vm);
        return ERR_CAST(pagemap);
    }
    *vm = (struct vm){
        .start = DIV_CEIL((uintptr_t)start, PAGE_SIZE),
        .end = (uintptr_t)end >> PAGE_SHIFT,
        .pagemap = pagemap,
        .refcount = REFCOUNT_INIT_ONE,
    };
    return vm;
}

void __vm_destroy(struct vm* vm) {
    ASSERT(vm != kernel_vm);
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

    pagemap_destroy(vm->pagemap);
    slab_free(&vm_slab, vm);
}

void vm_enter(struct vm* vm) {
    if (vm == current->vm)
        return;
    // Defer destroying the old vm until switching to the new pagemap
    struct vm* prev_vm FREE(vm) = NULL;
    SCOPED_LOCK(task, current);
    prev_vm = current->vm;
    current->vm = vm_ref(vm);
    pagemap_switch(vm->pagemap);
}

struct vm* vm_clone(struct vm* vm) {
    ASSERT(vm != kernel_vm);

    struct vm* new_vm FREE(vm) = ASSERT(slab_alloc(&vm_slab));
    if (IS_ERR(new_vm))
        return new_vm;

    *new_vm = (struct vm){
        .start = vm->start,
        .end = vm->end,
        .refcount = REFCOUNT_INIT_ONE,
    };

    SCOPED_LOCK(vm, new_vm);
    SCOPED_LOCK(vm, vm);

    struct pagemap* pagemap = ASSERT(pagemap_create());
    if (IS_ERR(pagemap))
        return ERR_CAST(pagemap);
    new_vm->pagemap = pagemap;

    for (const struct vm_region* it = vm_first_region(vm); it;
         it = vm_next_region(it)) {
        struct vm_region* new_region = ASSERT(vm_region_clone(new_vm, it));
        if (IS_ERR(new_region))
            return ERR_CAST(new_region);

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

    return TAKE_PTR(new_vm);
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

// Returns a positive value if the mapping to the page should be invalidated,
// 0 if the mapping can be reused, or a negative error code on failure.
NODISCARD static int get_page(struct vm_region* region, size_t index,
                              unsigned request, struct page** out_page) {
    ASSERT(vm_is_locked_by_current(region->vm));

    struct vm_obj* obj = region->obj;
    if (!obj)
        return -EFAULT;

    unsigned flags = region->flags | obj->flags;
    if (request & ~flags)
        return -EFAULT;

    if (!(request & (VM_READ | VM_WRITE | VM_EXEC))) {
        *out_page = NULL;
        return 0;
    }

    struct tree_node** new_node = &region->private_pages.root;
    struct tree_node* parent = NULL;
    if (!(flags & VM_SHARED)) {
        while (*new_node) {
            parent = *new_node;
            struct page* page = CONTAINER_OF(parent, struct page, tree_node);
            if (index < page->index) {
                new_node = &parent->left;
            } else if (index > page->index) {
                new_node = &parent->right;
            } else {
                *out_page = page_ref(page);
                return 0;
            }
        }
    }

    const struct vm_ops* vm_ops = ASSERT_PTR(obj->vm_ops);
    ASSERT_PTR(vm_ops->get_page);

    struct page* shared_page FREE(page) =
        vm_ops->get_page(obj, region->offset + index, request);
    if (IS_ERR(shared_page))
        return PTR_ERR(shared_page);
    if (!shared_page)
        return -EFAULT;

    if (!(request & VM_WRITE) || (flags & VM_SHARED)) {
        *out_page = TAKE_PTR(shared_page);
        return 0;
    }

    // Copy on write
    struct page* private_page = ASSERT(page_alloc());
    if (IS_ERR(private_page))
        return PTR_ERR(private_page);
    private_page->index = index;
    *new_node = &private_page->tree_node;
    page_ref(private_page);
    tree_insert(&region->private_pages, parent, *new_node);
    page_copy(private_page, shared_page);
    *out_page = private_page;
    return 1;
}

NODISCARD static int map_page(struct vm* vm, void* virt_addr,
                              unsigned request) {
    ASSERT(vm_is_locked_by_current(vm));

    struct vm_region* region = vm_find(vm, virt_addr);
    if (!region)
        return -EFAULT;

    struct vm_obj* obj = region->obj;
    if (!obj)
        return -EFAULT;

    SCOPED_LOCK(vm_obj, obj);

    size_t index = ((uintptr_t)virt_addr >> PAGE_SHIFT) - region->start;
    struct page* page FREE(page) = NULL;
    int result = get_page(region, index, request, &page);
    if (IS_ERR(result))
        return result;
    if (!page)
        return -EFAULT;

    uintptr_t page_addr = ROUND_DOWN((uintptr_t)virt_addr, PAGE_SIZE);
    unsigned flags = region->flags | obj->flags;
    if (!(request & VM_WRITE))
        flags &= ~VM_WRITE; // Trigger a page fault on the next write
    return pagemap_map(vm->pagemap, page_addr, page_to_pfn(page), 1, flags);
}

bool vm_handle_page_fault(void* virt_addr, unsigned flags) {
    struct vm* vm = virt_addr_to_vm(virt_addr);
    if (!vm)
        return false;

    bool write = flags & PAGE_FAULT_WRITE;
    bool user = flags & PAGE_FAULT_USER;
    bool instr = flags & PAGE_FAULT_INSTRUCTION;
    bool interruptible = flags & PAGE_FAULT_INTERRUPTIBLE;

    if (vm == kernel_vm) {
        if (user) {
            // User mode should not access kernel memory
            return false;
        }
    } else { // User address space
        if (!user && instr) {
            // Kernel mode should not execute user-space code
            return false;
        }
    }

    if (!user && !interruptible) {
        // Faulted in atomic context in kernel mode.
        // To prevent breaking atomicity, we cannot enable interrupts,
        // so we cannot handle the page fault.
        return false;
    }

    unsigned request = 0;
    if (write)
        request |= VM_WRITE;
    else
        request |= instr ? VM_EXEC : VM_READ;
    if (user)
        request |= VM_USER;

    SCOPED_ENABLE_INTERRUPTS();
    SCOPED_LOCK(vm, vm);
    return IS_OK(map_page(vm, virt_addr, request));
}

int vm_populate(struct vm* vm, void* virt_start_addr, void* virt_end_addr,
                unsigned request) {
    uintptr_t start = ROUND_DOWN((uintptr_t)virt_start_addr, PAGE_SIZE);
    uintptr_t end = ROUND_UP((uintptr_t)virt_end_addr, PAGE_SIZE);
    if (start >= end)
        return -EINVAL;
    if (!vm_contains(vm, (void*)start) || !vm_contains(vm, (void*)(end - 1)))
        return -EFAULT;

    SCOPED_LOCK(vm, vm);
    for (uintptr_t addr = start; addr < end; addr += PAGE_SIZE) {
        int rc = map_page(vm, (void*)addr, request);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

struct page* vm_get_page(struct vm* vm, void* virt_addr, unsigned request) {
    ASSERT(vm_is_locked_by_current(vm));

    struct vm_region* region = vm_find(vm, virt_addr);
    if (!region)
        return NULL;

    size_t index = ((uintptr_t)virt_addr >> PAGE_SHIFT) - region->start;
    struct page* page FREE(page) = NULL;
    int invalidate = get_page(region, index, request, &page);
    if (IS_ERR(invalidate))
        return ERR_PTR(invalidate);
    if (invalidate) {
        uintptr_t page_addr = ROUND_DOWN((uintptr_t)virt_addr, PAGE_SIZE);
        pagemap_unmap(vm->pagemap, page_addr, 1);
    }
    return TAKE_PTR(page);
}

int copy_from_vm(struct vm* vm, void* dest, const void* src, size_t n) {
    ASSERT(vm_is_locked_by_current(vm));
    size_t ncopied = 0;
    size_t page_offset = (uintptr_t)src % PAGE_SIZE;
    while (ncopied < n) {
        struct page* page FREE(page) =
            vm_get_page(vm, (unsigned char*)src + ncopied, VM_READ);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            return -EFAULT;
        size_t to_copy = MIN(PAGE_SIZE - page_offset, n - ncopied);
        copy_from_page((unsigned char*)dest + ncopied, page, page_offset,
                       to_copy);
        ncopied += to_copy;
        page_offset = 0;
    }
    return 0;
}

int copy_to_vm(struct vm* vm, void* dest, const void* src, size_t n) {
    ASSERT(vm_is_locked_by_current(vm));
    size_t ncopied = 0;
    size_t page_offset = (uintptr_t)dest % PAGE_SIZE;
    while (ncopied < n) {
        struct page* page FREE(page) =
            vm_get_page(vm, (unsigned char*)dest + ncopied, VM_WRITE);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            return -EFAULT;
        size_t to_copy = MIN(PAGE_SIZE - page_offset, n - ncopied);
        copy_to_page(page, (const unsigned char*)src + ncopied, page_offset,
                     to_copy);
        ncopied += to_copy;
        page_offset = 0;
    }
    return 0;
}

int vm_clear(struct vm* vm, void* to, size_t n) {
    ASSERT(vm_is_locked_by_current(vm));
    size_t ncleared = 0;
    size_t page_offset = (uintptr_t)to % PAGE_SIZE;
    while (ncleared < n) {
        struct page* page FREE(page) =
            vm_get_page(vm, (unsigned char*)to + ncleared, VM_WRITE);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            return -EFAULT;
        size_t to_clear = MIN(PAGE_SIZE - page_offset, n - ncleared);
        page_clear(page, page_offset, to_clear);
        ncleared += to_clear;
        page_offset = 0;
    }
    return 0;
}

ssize_t vm_strnlen(struct vm* vm, const char* str, size_t n) {
    ASSERT(vm_is_locked_by_current(vm));
    size_t offset = 0;
    size_t page_offset = (uintptr_t)str % PAGE_SIZE;
    while (offset < n) {
        struct page* page FREE(page) =
            vm_get_page(vm, (unsigned char*)str + offset, VM_READ);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            return -EFAULT;
        size_t to_read = MIN(PAGE_SIZE - page_offset, n - offset);
        char buffer[PAGE_SIZE];
        copy_from_page(buffer, page, page_offset, to_read);
        size_t len = strnlen(buffer, to_read);
        if (len < to_read)
            return offset + len;
        offset += to_read;
        page_offset = 0;
    }
    return n;
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
    ASSERT(vm_is_locked_by_current(vm));
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
    ASSERT(vm_is_locked_by_current(vm));
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
    ASSERT(vm_is_locked_by_current(vm));

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
        struct vm_region* region = ASSERT_OK(find_intersection(vm, start, end));
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
    ASSERT(vm_is_locked_by_current(vm));
    tree_remove(&vm->regions, &region->tree_node);
}

struct vm_region* vm_alloc(struct vm* vm, size_t npages) {
    ASSERT(vm_is_locked_by_current(vm));

    if (npages == 0)
        return ERR_PTR(-EINVAL);

    // slab_alloc() can allocate a new region, so it should be called
    // before vm_find_gap().
    struct vm_region* region = ASSERT(vm_region_create(vm, 0, 0));
    if (IS_ERR(region))
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
    ASSERT(vm_is_locked_by_current(vm));
    ASSERT((uintptr_t)virt_addr % PAGE_SIZE == 0);

    if (npages == 0)
        return ERR_PTR(-EINVAL);

    size_t start = (uintptr_t)virt_addr >> PAGE_SHIFT;
    size_t end = start + npages;
    if (end <= start)
        return ERR_PTR(-EOVERFLOW);
    if (start < vm->start || vm->end < end)
        return ERR_PTR(-ERANGE);

    struct vm_region* new_region = ASSERT(vm_region_create(vm, start, end));
    if (IS_ERR(new_region))
        return new_region;

    struct vm_region* region = ASSERT_OK(find_intersection(vm, start, end));

    // Free overlapping regions
    while (region && start < region->end) {
        struct vm_region* prev = vm_prev_region(region);
        size_t offset = MAX(start, region->start) - region->start;
        size_t overlap_npages = MIN(end, region->end) - region->start - offset;
        int rc = vm_region_free(region, offset, overlap_npages);
        if (IS_ERR(rc)) {
            // The only case it fails is when the region encompasses
            // [start, end) and the region gets split into two regions.
            // In this case, it is the only region that overlaps with
            // the new_region, so we don't have to worry about recovering
            // other regions that have been already removed.
            vm_region_destroy(new_region);
            return ERR_PTR(rc);
        }
        region = prev;
    }

    vm_insert_region(vm, new_region);

    return new_region;
}
