#include "private.h"
#include "vm.h"
#include <common/string.h>
#include <kernel/panic.h>

void vm_obj_ref(struct vm_obj* obj) {
    ASSERT(obj);
    ASSERT(obj->ref_count++ > 0);
}

void vm_obj_unref(struct vm_obj* obj) {
    if (!obj)
        return;
    ASSERT(obj->ref_count > 0);
    if (--obj->ref_count > 0)
        return;

    ASSERT(!obj->shared_regions);

    const struct vm_ops* vm_ops = obj->vm_ops;
    ASSERT(vm_ops);
    ASSERT(vm_ops->destroy_obj);
    vm_ops->destroy_obj(obj);
}

struct anon {
    struct vm_obj vm_obj;
    struct page* shared_pages;
};

static struct slab_cache anon_cache;

static void anon_destroy(struct vm_obj* obj) {
    struct anon* anon = CONTAINER_OF(obj, struct anon, vm_obj);
    pages_clear(&anon->shared_pages);
    slab_cache_free(&anon_cache, obj);
}

static struct page* zero_page;

static struct page* anon_get_page(struct vm_obj* obj, size_t offset,
                                  uint32_t error_code) {
    struct anon* anon = CONTAINER_OF(obj, struct anon, vm_obj);
    struct page* page = pages_get(anon->shared_pages, offset);
    if (page)
        return page;
    if (!(error_code & X86_PF_WRITE))
        return zero_page;
    page = pages_alloc_at(&anon->shared_pages, offset);
    if (IS_ERR(page))
        return page;
    void* kaddr = kmap_page(page);
    memset(kaddr, 0, PAGE_SIZE);
    kunmap(kaddr);
    return page;
}

static const struct vm_ops anon_vm_ops = {
    .destroy_obj = anon_destroy,
    .get_page = anon_get_page,
};

struct vm_obj* anon_create(void) {
    struct anon* anon = slab_cache_alloc(&anon_cache);
    if (IS_ERR(anon))
        return ERR_CAST(anon);
    *anon = (struct anon){
        .vm_obj =
            {
                .vm_ops = &anon_vm_ops,
                .ref_count = 1,
            },
    };
    return &anon->vm_obj;
}

struct phys {
    struct vm_obj vm_obj;
    size_t start;
    size_t end;
};

static struct slab_cache phys_cache;

static void phys_destroy(struct vm_obj* obj) {
    struct phys* phys = CONTAINER_OF(obj, struct phys, vm_obj);
    slab_cache_free(&phys_cache, phys);
}

static struct page* phys_get_page(struct vm_obj* obj, size_t offset,
                                  uint32_t error_code) {
    (void)error_code;
    struct phys* phys = CONTAINER_OF(obj, struct phys, vm_obj);
    size_t pfn = phys->start + offset;
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
    size_t start = phys_addr / PAGE_SIZE;
    size_t end = start + npages;
    if (end <= start)
        return ERR_PTR(-EOVERFLOW);

    struct phys* phys = slab_cache_alloc(&phys_cache);
    if (IS_ERR(phys))
        return ERR_CAST(phys);
    *phys = (struct phys){
        .vm_obj =
            {
                .vm_ops = &phys_vm_ops,
                .ref_count = 1,
            },
        .start = start,
        .end = end,
    };
    return &phys->vm_obj;
}

void vm_obj_init(void) {
    slab_cache_init(&anon_cache, sizeof(struct anon));
    slab_cache_init(&phys_cache, sizeof(struct phys));

    zero_page = page_alloc();
    ASSERT_OK(zero_page);
    void* kaddr = kmap_page(zero_page);
    memset(kaddr, 0, PAGE_SIZE);
    kunmap(kaddr);
}
