#include "memory.h"
#include "private.h"
#include <common/string.h>
#include <kernel/panic.h>

void vobj_ref(struct vobj* vobj) {
    ASSERT(vobj);
    ++vobj->ref_count;
}

void vobj_unref(struct vobj* vobj) {
    if (!vobj)
        return;
    ASSERT(vobj->ref_count > 0);
    if (--vobj->ref_count > 0)
        return;

    ASSERT(!vobj->regions);

    struct page* page = vobj->pages;
    while (page) {
        struct page* next = page->next;
        page_free(page);
        page = next;
    }
    vobj->pages = NULL;

    ASSERT(vobj->vm_ops->destroy_vobj);
    vobj->vm_ops->destroy_vobj(vobj);
}

struct vobj* vobj_clone(struct vobj* vobj) {
    ASSERT(vobj);
    const struct vm_ops* vm_ops = vobj->vm_ops;
    ASSERT(vm_ops);
    ASSERT(vm_ops->clone_vobj);
    return vm_ops->clone_vobj(vobj);
}

struct page* vobj_create_page(struct vobj* vobj, size_t offset) {
    ASSERT(spinlock_is_locked_by_current(&vobj->lock));

    struct page* prev = NULL;
    for (struct page* page = vobj->pages; page; page = page->next) {
        ASSERT(page->flags & PAGE_ALLOCATED);
        if (page->next)
            ASSERT(page->offset < page->next->offset);
        if (page->offset == offset)
            return ERR_PTR(-EEXIST);
        if (page->offset > offset)
            break;
        prev = page;
    }

    // struct page* page = page_alloc_committed();
    struct page* page = page_alloc();
    if (IS_ERR(page))
        return page;
    page->offset = offset;
    if (prev) {
        page->next = prev->next;
        prev->next = page;
    } else {
        page->next = vobj->pages;
        vobj->pages = page;
    }

    return page;
}

struct page* vobj_get_page(struct vobj* vobj, size_t offset) {
    ASSERT(spinlock_is_locked_by_current(&vobj->lock));
    for (struct page* page = vobj->pages; page; page = page->next) {
        ASSERT(page->flags & PAGE_ALLOCATED);
        if (page->next)
            ASSERT(page->offset < page->next->offset);
        if (page->offset == offset)
            return page;
        if (page->offset > offset)
            return NULL;
    }
    return NULL;
}

void vobj_remove_region(struct vobj* vobj, struct vm_region* region) {
    ASSERT(spinlock_is_locked_by_current(&vobj->lock));
    struct vm_region* prev = NULL;
    struct vm_region* it = vobj->regions;
    for (; it; it = it->next) {
        if (it == region)
            break;
        prev = it;
    }
    ASSERT(it);
    if (prev) {
        prev->shared_next = region->shared_next;
    } else {
        ASSERT(vobj->regions == region);
        vobj->regions = region->shared_next;
    }
}

static struct slab_cache anon_cache;
static struct page* zero_page;
static const struct vm_ops anon_vm_ops;

static void anon_destroy(struct vobj* vobj) {
    slab_cache_free(&anon_cache, vobj);
}

static struct vobj* anon_clone(struct vobj* vobj) {
    struct vobj* anon = anon_create();
    if (IS_ERR(anon))
        return ERR_CAST(anon);

    spinlock_lock(&vobj->lock);
    struct page* prev_cloned = NULL;
    for (struct page* page = vobj->pages; page; page = page->next) {
        struct page* cloned = page_alloc();
        if (IS_ERR(cloned)) {
            spinlock_unlock(&vobj->lock);
            vobj_unref(anon);
            return ERR_CAST(cloned);
        }
        *cloned = (struct page){
            .offset = page->offset,
            .flags = page->flags,
        };

        void* dest = kmap_page(cloned);
        void* src = kmap_page(page);
        memcpy(dest, src, PAGE_SIZE);
        kunmap(src);
        kunmap(dest);

        if (prev_cloned)
            prev_cloned->next = cloned;
        else
            anon->pages = cloned;
        prev_cloned = cloned;
    }
    spinlock_unlock(&vobj->lock);

    return anon;
}

static bool anon_handle_fault(struct vm_region* region, size_t offset,
                              uint32_t error_code) {
    struct vobj* vobj = region->vobj;
    struct page* page = vobj_get_page(vobj, region->offset + offset);
    bool new_page = false;
    unsigned vm_flags = region->flags;

    if (error_code & X86_PF_WRITE) {
        if (!page) {
            page = vobj_create_page(vobj, region->offset + offset);
            if (IS_ERR(page))
                return false;
            new_page = true;
        }
    } else {
        ASSERT(!(error_code & X86_PF_PROT));
        if (!page)
            page = zero_page;
        vm_flags &= ~VM_WRITE; // Trigger a write fault next time
    }

    size_t start = region->start + offset;
    ASSERT_OK(page_table_map(start, page_to_phys_index(page), 1,
                             vm_flags_to_pte_flags(vm_flags)));
    if (new_page)
        memset((void*)(start * PAGE_SIZE), 0, PAGE_SIZE);

    return true;
}

static const struct vm_ops anon_vm_ops = {
    .destroy_vobj = anon_destroy,
    .clone_vobj = anon_clone,
    .handle_fault = anon_handle_fault,
};

struct vobj* anon_create(void) {
    struct vobj* vobj = slab_cache_alloc(&anon_cache);
    if (IS_ERR(vobj))
        return ERR_CAST(vobj);
    *vobj = (struct vobj){
        .vm_ops = &anon_vm_ops,
        .ref_count = 1,
    };
    return vobj;
}

struct phys {
    struct vobj vobj;
    size_t start;
    size_t end;
};

static struct slab_cache phys_cache;

static void phys_destroy(struct vobj* vobj) {
    struct phys* phys = CONTAINER_OF(vobj, struct phys, vobj);
    slab_cache_free(&phys_cache, phys);
}

static struct vobj* phys_clone(struct vobj* vobj) {
    vobj_ref(vobj);
    return vobj;
}

static bool phys_handle_fault(struct vm_region* region, size_t offset,
                              uint32_t error_code) {
    ASSERT(!(error_code & X86_PF_PROT));
    struct phys* phys = CONTAINER_OF(region->vobj, struct phys, vobj);
    size_t phys_index = phys->start + region->offset + offset;
    ASSERT(phys_index < phys->end);
    int rc = page_table_map(region->start + offset, phys_index, 1,
                            vm_flags_to_pte_flags(region->flags));
    return IS_OK(rc);
}

static const struct vm_ops phys_vm_ops = {
    .destroy_vobj = phys_destroy,
    .clone_vobj = phys_clone,
    .handle_fault = phys_handle_fault,
};

struct vobj* phys_create(uintptr_t phys_addr, size_t npages) {
    ASSERT(phys_addr % PAGE_SIZE == 0);
    size_t start = phys_addr / PAGE_SIZE;
    size_t end = start + npages;
    if (end <= start)
        return ERR_PTR(-EOVERFLOW);

    struct phys* phys = slab_cache_alloc(&phys_cache);
    if (IS_ERR(phys))
        return ERR_CAST(phys);
    *phys = (struct phys){
        .vobj =
            {
                .vm_ops = &phys_vm_ops,
                .ref_count = 1,
            },
        .start = start,
        .end = end,
    };
    return &phys->vobj;
}

void vobj_init(void) {
    slab_cache_init(&anon_cache, sizeof(struct vobj));
    slab_cache_init(&phys_cache, sizeof(struct phys));

    zero_page = page_alloc();
    ASSERT(zero_page);
    void* zero_kaddr = kmap_page(zero_page);
    memset(zero_kaddr, 0, PAGE_SIZE);
    kunmap(zero_kaddr);
}
