#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>
#include <kernel/task/task.h>

void __vm_obj_destroy(struct vm_obj* obj) {
    ASSERT(!obj->shared_regions);

    const struct vm_ops* vm_ops = ASSERT_PTR(obj->vm_ops);
    ASSERT_PTR(vm_ops->destroy_obj);
    vm_ops->destroy_obj(obj);
}

void* vm_obj_map(struct vm_obj* obj, size_t offset, size_t npages,
                 unsigned flags) {
    SCOPED_LOCK(vm, kernel_vm);

    struct vm_region* region = ASSERT(vm_alloc(kernel_vm, npages));
    if (IS_ERR(region))
        return region;

    ASSERT_OK(vm_region_set_flags(region, 0, npages, flags, ~0));
    vm_region_set_obj(region, obj, offset);

    return vm_region_to_virt(region);
}

void vm_obj_unmap(void* virt_addr) {
    if (!virt_addr)
        return;

    SCOPED_LOCK(vm, kernel_vm);
    struct vm_region* region = ASSERT_PTR(vm_find(kernel_vm, virt_addr));
    ASSERT(ROUND_DOWN((uintptr_t)virt_addr, PAGE_SIZE) ==
           (uintptr_t)vm_region_to_virt(region));
    ASSERT_OK(vm_region_free(region, 0, region->end - region->start));
}

ssize_t vm_obj_read(struct vm_obj* obj, void* buffer, size_t count,
                    uint64_t offset) {
    SCOPED_LOCK(vm_obj, obj);

    const struct vm_ops* ops = ASSERT_PTR(obj->vm_ops);
    ASSERT_PTR(ops->get_page);

    size_t nread = 0;
    unsigned char* dest = buffer;
    size_t index = offset >> PAGE_SHIFT;
    size_t page_offset = offset % PAGE_SIZE;
    while (count > 0) {
        struct page* page FREE(page) = ops->get_page(obj, index, VM_READ);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            break;

        size_t to_copy = MIN(count, PAGE_SIZE - page_offset);
        copy_from_page(dest, page, page_offset, to_copy);
        count -= to_copy;
        nread += to_copy;
        dest += to_copy;
        ++index;
        page_offset = 0;
    }
    return nread;
}

ssize_t vm_obj_write(struct vm_obj* obj, const void* buffer, size_t count,
                     uint64_t offset) {
    SCOPED_LOCK(vm_obj, obj);

    const struct vm_ops* ops = ASSERT_PTR(obj->vm_ops);
    ASSERT_PTR(ops->get_page);

    size_t nwritten = 0;
    const unsigned char* src = buffer;
    size_t index = offset >> PAGE_SHIFT;
    size_t page_offset = offset % PAGE_SIZE;
    while (count > 0) {
        struct page* page FREE(page) = ops->get_page(obj, index, VM_WRITE);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page) {
            if (nwritten == 0)
                return -ENOSPC;
            break;
        }

        size_t to_copy = MIN(count, PAGE_SIZE - page_offset);
        copy_to_page(page, src, page_offset, to_copy);
        count -= to_copy;
        nwritten += to_copy;
        src += to_copy;
        ++index;
        page_offset = 0;
    }
    return nwritten;
}

int vm_obj_invalidate_mappings(const struct vm_obj* obj, size_t offset,
                               size_t npages) {
    ASSERT(vm_obj_is_locked_by_current(obj));
    size_t end = offset + npages;
    if (end < offset)
        return -EOVERFLOW;
    for (const struct vm_region* region = obj->shared_regions; region;
         region = region->shared_next) {
        size_t region_end = region->offset + (region->end - region->start);
        if (region_end <= offset || end <= region->offset)
            continue;

        size_t overlap_start = MAX(offset, region->offset);
        size_t overlap_offset = overlap_start - region->offset;
        size_t overlap_npages = MIN(end, region_end) - overlap_start;
        if (overlap_npages == 0)
            continue;

        pagemap_unmap(region->vm->pagemap,
                      (region->start + overlap_offset) << PAGE_SHIFT,
                      overlap_npages);
    }
    return 0;
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

static struct page* zero_page; // The page filled with zeros

static struct page* anon_get_page(struct vm_obj* obj, size_t index,
                                  unsigned request) {
    SCOPED_LOCK(vm_obj, obj);
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
            return page_ref(page);
    }

    if (!(request & VM_WRITE))
        return page_ref(zero_page);

    // Invalidate mappings to zero_page
    int rc = vm_obj_invalidate_mappings(obj, index, 1);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    struct page* page = ASSERT(page_alloc());
    if (IS_ERR(page))
        return page;
    page->index = index;
    page_clear(page, 0, PAGE_SIZE);

    *new_node = &page->tree_node;
    page_ref(page);
    tree_insert(&anon->shared_pages, parent, *new_node);

    return page;
}

static const struct vm_ops anon_vm_ops = {
    .destroy_obj = anon_destroy,
    .get_page = anon_get_page,
};

struct vm_obj* anon_create(void) {
    struct anon* anon = ASSERT(slab_alloc(&anon_slab));
    if (IS_ERR(anon))
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
                                  unsigned request) {
    (void)request;
    struct phys* phys = CONTAINER_OF(obj, struct phys, vm_obj);
    size_t pfn = phys->start + index;
    if (phys->end <= pfn)
        return NULL;
    struct page* page = page_get(pfn);
    if (!page)
        return ERR_PTR(-EFAULT);
    return page;
}

static const struct vm_ops phys_vm_ops = {
    .destroy_obj = phys_destroy,
    .get_page = phys_get_page,
};

struct vm_obj* phys_create(phys_addr_t phys_addr, size_t npages) {
    ASSERT(phys_addr % PAGE_SIZE == 0);
    size_t start = phys_addr >> PAGE_SHIFT;
    size_t end = start + npages;
    if (end <= start)
        return ERR_PTR(-EOVERFLOW);

    struct phys* phys = ASSERT(slab_alloc(&phys_slab));
    if (IS_ERR(phys))
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

void* phys_map(phys_addr_t phys_addr, size_t size, unsigned vm_flags) {
    phys_addr_t aligned_addr = ROUND_DOWN(phys_addr, PAGE_SIZE);
    size_t npages = DIV_CEIL(phys_addr - aligned_addr + size, PAGE_SIZE);

    struct vm_obj* phys FREE(vm_obj) =
        ASSERT(phys_create(aligned_addr, npages));
    if (IS_ERR(phys))
        return phys;

    unsigned char* addr =
        ASSERT(vm_obj_map(phys, 0, npages, vm_flags | VM_SHARED));
    if (IS_ERR(addr))
        return addr;

    int rc =
        vm_populate(kernel_vm, addr, addr + (npages << PAGE_SHIFT), vm_flags);
    if (IS_ERR(rc)) {
        vm_obj_unmap(addr);
        return ERR_PTR(rc);
    }

    return addr + (phys_addr - aligned_addr);
}

void phys_unmap(void* virt_addr) { vm_obj_unmap(virt_addr); }

void vm_obj_init(void) {
    SLAB_INIT_FOR_TYPE(&anon_slab, "anon", struct anon);
    SLAB_INIT_FOR_TYPE(&phys_slab, "phys", struct phys);

    zero_page = ASSERT_PTR(page_alloc());
    page_clear(zero_page, 0, PAGE_SIZE);
}
