#include "memory.h"
#include "private.h"
#include <common/string.h>
#include <kernel/panic.h>

void vm_obj_ref(struct vm_obj* obj) {
    ASSERT(obj);
    ++obj->ref_count;
}

void vm_obj_unref(struct vm_obj* obj) {
    if (!obj)
        return;
    ASSERT(obj->ref_count > 0);
    if (--obj->ref_count > 0)
        return;

    ASSERT(!obj->shared_regions);
    page_set_clear(&obj->shared_pages);

    ASSERT(obj->vm_ops->destroy_obj);
    obj->vm_ops->destroy_obj(obj);
}

static struct slab_cache anon_cache;
static struct page* zero_page;
static const struct vm_ops anon_vm_ops;

static void anon_destroy(struct vm_obj* obj) {
    slab_cache_free(&anon_cache, obj);
}

static struct page* anon_populate(struct vm_obj* obj, size_t offset,
                                  uint32_t error_code) {
    if (!(error_code & X86_PF_WRITE))
        return zero_page;
    struct page* page = page_set_alloc_at(&obj->shared_pages, offset);
    if (IS_ERR(page))
        return page;
    void* kaddr = kmap_page(page);
    memset(kaddr, 0, PAGE_SIZE);
    kunmap(kaddr);
    return page;
}

static const struct vm_ops anon_vm_ops = {
    .destroy_obj = anon_destroy,
    .populate = anon_populate,
};

struct vm_obj* anon_create(void) {
    struct vm_obj* obj = slab_cache_alloc(&anon_cache);
    if (IS_ERR(obj))
        return ERR_CAST(obj);
    *obj = (struct vm_obj){
        .vm_ops = &anon_vm_ops,
        .ref_count = 1,
    };
    return obj;
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

static struct page* phys_populate(struct vm_obj* obj, size_t offset,
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
    .populate = phys_populate,
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
    slab_cache_init(&anon_cache, sizeof(struct vm_obj));
    slab_cache_init(&phys_cache, sizeof(struct phys));

    zero_page = page_alloc();
    ASSERT_OK(zero_page);
    void* kaddr = kmap_page(zero_page);
    memset(kaddr, 0, PAGE_SIZE);
    kunmap(kaddr);
}
