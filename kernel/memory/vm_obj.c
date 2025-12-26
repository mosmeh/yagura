#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>
#include <kernel/task.h>

void __vm_obj_destroy(struct vm_obj* obj) {
    ASSERT(!obj->shared_regions);

    const struct vm_ops* vm_ops = obj->vm_ops;
    ASSERT(vm_ops);
    ASSERT(vm_ops->destroy_obj);
    vm_ops->destroy_obj(obj);
}

void* vm_obj_map(struct vm_obj* obj, size_t offset, size_t npages,
                 unsigned flags) {
    mutex_lock(&kernel_vm->lock);

    struct vm_region* region = vm_alloc(kernel_vm, npages);
    if (IS_ERR(ASSERT(region))) {
        mutex_unlock(&kernel_vm->lock);
        return ERR_CAST(region);
    }

    ASSERT_OK(vm_region_set_flags(region, 0, npages, flags, ~0));
    vm_region_set_obj(region, obj, offset);

    mutex_unlock(&kernel_vm->lock);

    return vm_region_to_virt(region);
}

void vm_obj_unmap(void* virt_addr) {
    if (!virt_addr)
        return;

    mutex_lock(&kernel_vm->lock);
    struct vm_region* region = vm_find(kernel_vm, virt_addr);
    ASSERT(region);
    ASSERT(ROUND_DOWN((uintptr_t)virt_addr, PAGE_SIZE) ==
           (uintptr_t)vm_region_to_virt(region));
    ASSERT_OK(vm_region_free(region, 0, region->end - region->start));
    mutex_unlock(&kernel_vm->lock);
}

int vm_obj_invalidate_mappings(const struct vm_obj* obj, size_t offset,
                               size_t npages) {
    ASSERT(mutex_is_locked_by_current(&obj->lock));
    int rc = 0;
    struct vm* original_vm = current->vm;
    for (const struct vm_region* region = obj->shared_regions; region;
         region = region->shared_next) {
        if (region->offset + (region->end - region->start) <= offset)
            continue;
        if (region->offset >= offset + npages)
            continue;

        struct vm* vm = region->vm;
        if (vm != kernel_vm && vm != current->vm)
            vm_enter(vm);

        size_t region_offset = offset - region->offset;
        size_t region_npages =
            MIN(npages, region->end - region->start - region_offset);

        mutex_lock(&vm->lock);
        rc = vm_region_invalidate(region, region_offset, region_npages);
        mutex_unlock(&vm->lock);

        if (IS_ERR(rc))
            break;
    }
    vm_enter(original_vm);
    return rc;
}

struct anon {
    struct vm_obj vm_obj;
    struct tree shared_pages; // Pages referenced by VM_SHARED regions
};

static struct slab anon_slab;

static void anon_destroy(struct vm_obj* obj) {
    struct anon* anon = CONTAINER_OF(obj, struct anon, vm_obj);
    pages_clear(&anon->shared_pages);
    slab_free(&anon_slab, obj);
}

static struct page* zero_page;

static struct page* anon_get_page(struct vm_obj* obj, size_t index,
                                  bool write) {
    ASSERT(mutex_is_locked_by_current(&obj->lock));
    struct anon* anon = CONTAINER_OF(obj, struct anon, vm_obj);

    struct tree_node** new_node = &anon->shared_pages.root;
    struct tree_node* parent = NULL;
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

    if (!write)
        return zero_page;

    // Invalidate mappings to zero_page
    int rc = vm_obj_invalidate_mappings(obj, index, 1);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    struct page* page = page_alloc();
    if (IS_ERR(ASSERT(page)))
        return page;
    page->index = index;
    page_fill(page, 0, 0, PAGE_SIZE);

    *new_node = &page->tree_node;
    tree_insert(&anon->shared_pages, parent, *new_node);

    return page;
}

static const struct vm_ops anon_vm_ops = {
    .destroy_obj = anon_destroy,
    .get_page = anon_get_page,
};

struct vm_obj* anon_create(void) {
    struct anon* anon = slab_alloc(&anon_slab);
    if (IS_ERR(ASSERT(anon)))
        return ERR_CAST(anon);
    *anon = (struct anon){
        .vm_obj =
            {
                .vm_ops = &anon_vm_ops,
                .refcount = REFCOUNT_INIT_ONE,
            },
    };
    return &anon->vm_obj;
}

struct phys {
    struct vm_obj vm_obj;
    size_t start; // Start pfn (inclusive)
    size_t end;   // End pfn (exclusive)
};

static struct slab phys_slab;

static void phys_destroy(struct vm_obj* obj) {
    struct phys* phys = CONTAINER_OF(obj, struct phys, vm_obj);
    slab_free(&phys_slab, phys);
}

static struct page* phys_get_page(struct vm_obj* obj, size_t index,
                                  bool write) {
    (void)write;
    ASSERT(mutex_is_locked_by_current(&obj->lock));
    struct phys* phys = CONTAINER_OF(obj, struct phys, vm_obj);
    size_t pfn = phys->start + index;
    if (phys->end <= pfn)
        return ERR_PTR(-EFAULT);
    return page_get(pfn);
}

static const struct vm_ops phys_vm_ops = {
    .destroy_obj = phys_destroy,
    .get_page = phys_get_page,
};

struct vm_obj* phys_create(uintptr_t phys_addr, size_t npages) {
    ASSERT(phys_addr % PAGE_SIZE == 0);
    size_t start = phys_addr >> PAGE_SHIFT;
    size_t end = start + npages;
    if (end <= start)
        return ERR_PTR(-EOVERFLOW);

    struct phys* phys = slab_alloc(&phys_slab);
    if (IS_ERR(ASSERT(phys)))
        return ERR_CAST(phys);
    *phys = (struct phys){
        .vm_obj =
            {
                .vm_ops = &phys_vm_ops,
                .refcount = REFCOUNT_INIT_ONE,
            },
        .start = start,
        .end = end,
    };
    return &phys->vm_obj;
}

void* phys_map(uintptr_t phys_addr, size_t size, unsigned vm_flags) {
    uintptr_t aligned_addr = ROUND_DOWN(phys_addr, PAGE_SIZE);
    size_t npages = DIV_CEIL(phys_addr - aligned_addr + size, PAGE_SIZE);

    struct vm_obj* phys FREE(vm_obj) = phys_create(aligned_addr, npages);
    if (IS_ERR(ASSERT(phys)))
        return ERR_CAST(phys);

    unsigned char* addr = vm_obj_map(phys, 0, npages, vm_flags | VM_SHARED);
    if (IS_ERR(ASSERT(addr)))
        return addr;
    return addr + (phys_addr - aligned_addr);
}

void phys_unmap(void* virt_addr) { vm_obj_unmap(virt_addr); }

void vm_obj_init(void) {
    slab_init(&anon_slab, "anon", sizeof(struct anon));
    slab_init(&phys_slab, "phys", sizeof(struct phys));

    zero_page = page_alloc();
    ASSERT_PTR(zero_page);
    page_fill(zero_page, 0, 0, PAGE_SIZE);
}
