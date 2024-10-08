#include "memory.h"
#include "private.h"
#include <common/string.h>
#include <kernel/lock.h>
#include <kernel/panic.h>

static struct slab_cache anon_cache;
static struct page* zero_page;
static const struct vm_ops anon_vm_ops;

static void anon_destroy(struct vobj* vobj) {
    slab_cache_free(&anon_cache, vobj);
}

static struct vobj* anon_clone(struct vobj* vobj) {
    struct vobj* cloned = slab_cache_alloc(&anon_cache);
    if (IS_ERR(cloned))
        return ERR_CAST(cloned);
    *cloned = (struct vobj){
        .ops = &anon_vm_ops,
        .ref_count = 1,
    };
    return cloned;
}

static bool anon_handle_fault(struct vm_region* region, size_t offset,
                              uint32_t error_code) {
    struct vobj* vobj = region->vobj;
    size_t start = region->start + offset;
    struct page* page = vobj_get_page(vobj, offset);
    bool new_page = false;
    uint32_t vm_flags = region->flags;

    if (error_code & X86_PF_WRITE) {
        if (!page) {
            page = vobj_create_page(vobj, offset);
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
    ASSERT_OK(page_table_map(region->start + offset, page_to_phys_index(page),
                             1, vm_flags_to_pte_flags(vm_flags)));

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
        .ops = &anon_vm_ops,
        .ref_count = 1,
    };
    return vobj;
}

void kmalloc_init(void) {
    slab_cache_init(&anon_cache, sizeof(struct vobj));

    zero_page = page_alloc();
    ASSERT(zero_page);
    void* zero_kaddr = kmap_page(zero_page);
    memset(zero_kaddr, 0, PAGE_SIZE);
    kunmap(zero_kaddr);
}

void* kmalloc(size_t size) {
    size_t num_pages = DIV_CEIL(size, PAGE_SIZE);
    /*if (!page_commit(num_pages))
        return NULL;*/

    struct vobj* vobj = anon_create();
    if (IS_ERR(vobj))
        return NULL;

    spinlock_lock(&kernel_vm->lock);
    struct vm_region* region = vm_alloc(kernel_vm, num_pages);
    if (IS_ERR(region)) {
        spinlock_unlock(&kernel_vm->lock);
        vobj_unref(vobj);
        return NULL;
    }

    region->flags = VM_READ | VM_WRITE;
    vm_region_set_vobj(region, vobj);

    spinlock_unlock(&kernel_vm->lock);

    return (void*)(region->start * PAGE_SIZE);
}

void* kaligned_alloc(size_t alignment, size_t size) {
    ASSERT(alignment <= PAGE_SIZE);
    return kmalloc(size); // kmalloc already returns page-aligned addresses
}

void* krealloc(void* ptr, size_t new_size) {
    if (!ptr)
        return kmalloc(new_size);

    spinlock_lock(&kernel_vm->lock);

    struct vm_region* region = vm_find(kernel_vm, ptr);
    ASSERT(region);
    ASSERT((uintptr_t)ptr == region->start * PAGE_SIZE);

    size_t new_npages = DIV_CEIL(new_size, PAGE_SIZE);
    size_t old_npages = region->end - region->start;
    if (new_npages == old_npages) {
        spinlock_unlock(&kernel_vm->lock);
        return ptr;
    }
    /*if (new_npages < old_npages)
        page_uncommit(old_npages - new_npages);
    else if (!page_commit(new_npages - old_npages))
        return NULL;*/

    int rc = vm_region_resize(region, new_npages);
    if (IS_ERR(rc)) {
        spinlock_unlock(&kernel_vm->lock);
        return NULL;
    }

    // The region might have been moved
    return (void*)(region->start * PAGE_SIZE);
}

void kfree(void* ptr) {
    if (!ptr)
        return;

    spinlock_lock(&kernel_vm->lock);
    struct vm_region* region = vm_find(kernel_vm, ptr);
    ASSERT(region);
    ASSERT((uintptr_t)ptr == region->start * PAGE_SIZE);
    ASSERT_OK(vm_region_free(region, 0, region->end - region->start));
    spinlock_unlock(&kernel_vm->lock);
}

char* kstrdup(const char* src) {
    if (!src)
        return NULL;

    size_t len = strlen(src);
    char* buf = kmalloc((len + 1) * sizeof(char));
    if (!buf)
        return NULL;

    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}

char* kstrndup(const char* src, size_t n) {
    if (!src)
        return NULL;

    size_t len = strnlen(src, n);
    char* buf = kmalloc((len + 1) * sizeof(char));
    if (!buf)
        return NULL;

    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}
