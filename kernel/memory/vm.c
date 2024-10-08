#include "memory.h"
#include "private.h"
#include <common/string.h>
#include <kernel/kmsg.h>
#include <kernel/lock.h>
#include <kernel/panic.h>
#include <kernel/task.h>
#include <stdint.h>

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

    ASSERT(vobj->ops->destroy_vobj);
    vobj->ops->destroy_vobj(vobj);
}

struct page* vobj_create_page(struct vobj* vobj, size_t offset) {
    spinlock_lock(&vobj->lock);

    struct page* prev = NULL;
    for (struct page* page = vobj->pages; page; page = page->next) {
        if (prev)
            ASSERT(prev->offset < page->offset);
        if (page->offset == offset) {
            spinlock_unlock(&vobj->lock);
            return ERR_PTR(-EEXIST);
        }
        if (page->offset > offset)
            break;
        prev = page;
    }

    // struct page* page = page_alloc_committed();
    struct page* page = page_alloc();
    if (IS_ERR(page))
        goto fail;
    *page = (struct page){
        .offset = offset,
    };
    if (prev) {
        page->next = prev->next;
        prev->next = page;
    } else {
        page->next = vobj->pages;
        vobj->pages = page;
    }

fail:
    spinlock_unlock(&vobj->lock);
    return page;
}

struct page* vobj_get_page(struct vobj* vobj, size_t offset) {
    spinlock_lock(&vobj->lock);
    struct page* page = vobj->pages;
    for (; page; page = page->next) {
        if (page->offset == offset)
            break;
        if (page->offset > offset) {
            page = NULL;
            break;
        }
    }
    spinlock_unlock(&vobj->lock);
    return page;
}

struct vm* kernel_vm;

static struct slab_cache vm_region_cache;

NODISCARD static void vm_region_destroy(struct vm_region* region) {
    struct vobj* vobj = region->vobj;
    if (vobj) {
        spinlock_lock(&vobj->lock);
        struct vm_region* prev = NULL;
        struct vm_region* it = vobj->regions;
        while (it) {
            if (it == region)
                break;
            prev = it;
            it = it->shared_next;
        }
        ASSERT(it);
        if (prev)
            prev->shared_next = region->shared_next;
        else
            vobj->regions = region->shared_next;
        spinlock_unlock(&vobj->lock);

        vobj_unref(vobj);
    }
    slab_cache_free(&vm_region_cache, region);
}

void vm_init(size_t kernel_heap_start) {
    static struct vm vm;
    kernel_vm = &vm;
    vm = (struct vm){
        .start = kernel_heap_start,
        .end = KERNEL_HEAP_END / PAGE_SIZE,
        .page_directory = kernel_page_directory,
        .ref_count = 1,
    };

    slab_cache_init(&vm_region_cache, sizeof(struct vm_region));
}

struct vm* vm_create(void* start, void* end) {
    struct vm* vm = kmalloc(sizeof(struct vm));
    if (!vm)
        return ERR_PTR(-ENOMEM);
    struct page_directory* page_directory = page_directory_create();
    if (IS_ERR(page_directory)) {
        kfree(vm);
        return ERR_CAST(page_directory);
    }
    *vm = (struct vm){
        .start = DIV_CEIL((uintptr_t)start, PAGE_SIZE),
        .end = (uintptr_t)end / PAGE_SIZE,
        .page_directory = page_directory,
        .ref_count = 1,
    };
    return vm;
}

void vm_ref(struct vm* vm) {
    ASSERT(vm);
    ASSERT(vm != kernel_vm);
    ++vm->ref_count;
}

void vm_unref(struct vm* vm) {
    if (!vm)
        return;
    ASSERT(vm != kernel_vm);
    ASSERT(vm->ref_count > 0);
    if (--vm->ref_count > 0)
        return;

    struct vm_region* region = vm->regions;
    while (region) {
        struct vm_region* next = region->next;
        vm_region_destroy(region);
        region = next;
    }

    page_directory_destroy(vm->page_directory);
    kfree(vm);
}

void vm_enter(struct vm* vm) {
    ASSERT(current);
    // current->vm needs to be updated BEFORE switching page directory.
    // Otherwise, when we are preempted between the two operations,
    // current->vm's page directory will be out of sync with the actual
    // active page directory.
    current->vm = vm;
    page_directory_switch(vm->page_directory);
}

struct vm* vm_clone(void) {
    ASSERT(current);
    struct vm* vm = current->vm;
    ASSERT(vm != kernel_vm);

    struct vm* new_vm = kmalloc(sizeof(struct vm));
    if (!new_vm)
        return ERR_PTR(-ENOMEM);

    *new_vm = (struct vm){
        .start = vm->start,
        .end = vm->end,
        .ref_count = 1,
    };

    spinlock_lock(&vm->lock);
    int ret = 0;

    struct page_directory* page_directory = page_directory_create();
    if (IS_ERR(page_directory)) {
        ret = PTR_ERR(page_directory);
        goto fail;
    }

    new_vm->page_directory = page_directory;

    struct vm_region* it = vm->regions;
    struct vm_region* prev_cloned = NULL;
    while (it) {
        struct vm_region* cloned = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(cloned)) {
            ret = PTR_ERR(cloned);
            goto fail;
        }

        *cloned = (struct vm_region){
            .vm = new_vm,
            .start = it->start,
            .end = it->end,
            .flags = it->flags,
            .prev = prev_cloned,
        };

        struct vobj* vobj = it->vobj;
        if (it->flags & VM_SHARED) {
            vobj_ref(vobj);
            vm_region_set_vobj(cloned, vobj);
        } else {
            ASSERT(vobj->ops->clone_vobj);
            vobj = vobj->ops->clone_vobj(vobj);
            if (IS_ERR(vobj)) {
                ret = PTR_ERR(vobj);
                slab_cache_free(&vm_region_cache, cloned);
                goto fail;
            }
        }
        cloned->vobj = vobj;

        if (prev_cloned)
            prev_cloned->next = cloned;
        else
            new_vm->regions = cloned;
        prev_cloned = cloned;

        it = it->next;
    }

    spinlock_unlock(&vm->lock);
    return new_vm;

fail:
    spinlock_unlock(&vm->lock);
    vm_unref(new_vm);
    return ERR_PTR(ret);
}

bool vm_handle_page_fault(uintptr_t addr, uint32_t error_code) {
    struct vm* vm = current ? current->vm : kernel_vm;

    spinlock_lock(&vm->lock);
    bool ret = false;

    struct vm_region* region = vm_find(vm, (void*)addr);
    if (!region)
        goto fail;
    if (error_code & X86_PF_WRITE) {
        if (!(region->flags & VM_WRITE))
            goto fail;
    } else if (!(region->flags & VM_READ)) {
        goto fail;
    }

    struct vobj* vobj = region->vobj;
    if (!vobj)
        goto fail;
    spinlock_lock(&vobj->lock);
    size_t offset = addr / PAGE_SIZE - region->start;
    ASSERT(vobj->ops->handle_fault);
    if (!vobj->ops->handle_fault(region, offset, error_code)) {
        spinlock_unlock(&vobj->lock);
        goto fail;
    }

    ret = true;
fail:
    spinlock_unlock(&vm->lock);
    return ret;
}

struct vm_region* vm_find(struct vm* vm, void* virt_addr) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));
    size_t index = (uintptr_t)virt_addr / PAGE_SIZE;
    struct vm_region* it = vm->regions;
    while (it) {
        if (it->next)
            ASSERT(it->end <= it->next->start);
        if (it->start <= index && index < it->end)
            return it;
        it = it->next;
    }
    return NULL;
}

struct vm_region* vm_find_gap(struct vm* vm, size_t npages, size_t* start) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));

    if (vm->start + npages > vm->end)
        return ERR_PTR(-ENOMEM);
    if (!vm->regions) {
        if (start)
            *start = vm->start;
        return NULL;
    }

    struct vm_region* prev = NULL;
    struct vm_region* it = vm->regions;
    while (it) {
        if (it->next)
            ASSERT(it->end <= it->next->start);
        if (prev && prev->end + npages <= it->start) {
            if (start)
                *start = prev->end;
            return prev;
        }
        prev = it;
        it = it->next;
    }
    if (prev && prev->end + npages <= vm->end) {
        if (start)
            *start = prev->end;
        return prev;
    }

    kprint("vm: out of virtual memory\n");
    return ERR_PTR(-ENOMEM);
}

void vm_insert_region_after(struct vm* vm, struct vm_region* cursor,
                            struct vm_region* inserted) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));
    if (cursor) {
        ASSERT(cursor->end <= inserted->start);
        inserted->prev = cursor;
        inserted->next = cursor->next;
        if (cursor->next) {
            ASSERT(inserted->end <= cursor->next->start);
            cursor->next->prev = inserted;
        }
        cursor->next = inserted;
    } else {
        inserted->prev = NULL;
        inserted->next = vm->regions;
        if (vm->regions) {
            ASSERT(inserted->end <= vm->regions->start);
            vm->regions->prev = inserted;
        }
        vm->regions = inserted;
    }
}

void vm_remove_region(struct vm* vm, struct vm_region* region) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));
    if (region->prev)
        region->prev->next = region->next;
    else
        vm->regions = region->next;
    if (region->next)
        region->next->prev = region->prev;
    region->prev = region->next = NULL;
}

struct vm_region* vm_alloc(struct vm* vm, size_t npages) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));

    if (npages == 0)
        return ERR_PTR(-EINVAL);

    struct vm_region* region = slab_cache_alloc(&vm_region_cache);
    if (IS_ERR(region))
        return ERR_PTR(region);

    size_t start;
    struct vm_region* cursor = vm_find_gap(vm, npages, &start);
    if (IS_ERR(cursor)) {
        slab_cache_free(&vm_region_cache, region);
        return ERR_CAST(cursor);
    }

    *region = (struct vm_region){
        .vm = vm,
        .start = start,
        .end = start + npages,
    };
    vm_insert_region_after(vm, cursor, region);

    return region;
}

struct vm_region* vm_alloc_at(struct vm* vm, void* virt_addr, size_t npages) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));

    if (npages == 0)
        return ERR_PTR(-EINVAL);

    size_t start = (uintptr_t)virt_addr / PAGE_SIZE;
    size_t end = DIV_CEIL((uintptr_t)virt_addr, PAGE_SIZE) + npages;
    if (start < vm->start || vm->end < end)
        return ERR_PTR(-ERANGE);
    if (end <= start)
        return ERR_PTR(-EOVERFLOW);

    struct vm_region* region = slab_cache_alloc(&vm_region_cache);
    if (IS_ERR(region))
        return ERR_PTR(region);

    int ret = 0;

    // Check if the range is already occupied
    struct vm_region* prev = NULL;
    struct vm_region* it = vm->regions;
    while (it && it->start < start) {
        if (it->end > start) {
            ret = -EEXIST;
            goto fail;
        }
        prev = it;
        it = it->next;
    }
    if (prev && prev->end > start && prev->start < end) {
        ret = -EEXIST;
        goto fail;
    }

    *region = (struct vm_region){
        .vm = vm,
        .start = start,
        .end = end,
    };
    vm_insert_region_after(vm, prev, region);

    return region;

fail:
    slab_cache_free(&vm_region_cache, region);
    return ERR_PTR(ret);
}

void vm_region_set_vobj(struct vm_region* region, struct vobj* vobj) {
    ASSERT(spinlock_is_locked_by_current(&region->vm->lock));
    ASSERT(!region->vobj);
    ASSERT(!region->shared_next);
    ASSERT(vobj);

    spinlock_lock(&vobj->lock);
    region->vobj = vobj;
    region->shared_next = vobj->regions;
    vobj->regions = region;
    spinlock_unlock(&vobj->lock);
}

int vm_region_resize(struct vm_region* region, size_t new_npages) {
    ASSERT(spinlock_is_locked_by_current(&region->vm->lock));

    if (new_npages == 0)
        return -EINVAL;

    size_t old_npages = region->end - region->start;
    if (old_npages == new_npages)
        return 0;

    // Shrink the region
    if (new_npages < old_npages) {
        region->end = region->start + new_npages;
        page_table_unmap(region->end, old_npages - new_npages);
        return 0;
    }

    // If the region is the last one or there is enough space after the
    // region, we can simply extend the region
    if (!region->next || region->start + new_npages < region->next->start) {
        region->end = region->start + new_npages;
        return 0;
    }

    // Otherwise, we need to allocate a new range
    struct vm* vm = region->vm;
    size_t new_start;
    struct vm_region* cursor = vm_find_gap(vm, new_npages, &new_start);
    if (IS_ERR(cursor))
        return ERR_PTR(cursor);

    // Unmap the old range
    page_table_unmap(region->start, old_npages);

    region->start = new_start;
    region->end = new_start + new_npages;

    vm_remove_region(vm, region);
    vm_insert_region_after(vm, cursor, region);

    return 0;
}

static uint32_t masked_set(uint32_t old, uint32_t new, uint32_t mask) {
    return (~mask & old) | (mask & new);
}

int vm_region_set_flags(struct vm_region* region, size_t offset, size_t npages,
                        uint32_t flags, uint32_t mask) {
    ASSERT(spinlock_is_locked_by_current(&region->vm->lock));

    if (npages == 0)
        return -EINVAL;
    if (flags & ~mask)
        return -EINVAL;
    if ((flags & VM_WRITE) && !(flags & VM_READ)) {
        // Write-only mapping is not possible with x86 paging
        return -EINVAL;
    }

    size_t start = region->start + offset;
    size_t end = start + npages;

    if (start < region->start || region->end < end)
        return -EINVAL;
    if (end <= start)
        return -EOVERFLOW;
    if (region->flags == flags)
        return 0;

    struct vm* vm = region->vm;
    int old_flags = region->flags;
    if (offset == 0 && end == region->end) {
        // Modify the whole region
        region->flags = masked_set(region->flags, flags, mask);
    } else if (offset == 0) {
        // Split the region into two.
        // Left (`region`): [start, start + size) with new flags
        // Right (`right_region`): [start + size, end) with old flags
        struct vm_region* right_region = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);
        region->end = end;
        region->flags = masked_set(old_flags, flags, mask);
        vobj_ref(region->vobj);
        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .offset = region->offset + npages,
            .flags = old_flags,
            .vobj = region->vobj,
        };
        vm_insert_region_after(vm, region, right_region);
    } else if (end == region->end) {
        // Split the region into two.
        // Left (`region`): [start, addr) with old flags
        // Right (`right_region`): [addr, end) with new flags
        struct vm_region* right_region = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);
        region->end = start;
        vobj_ref(region->vobj);
        *right_region = (struct vm_region){
            .vm = vm,
            .start = start,
            .end = end,
            .offset = region->offset + offset,
            .flags = masked_set(old_flags, flags, mask),
            .vobj = region->vobj,
        };
        vm_insert_region_after(vm, region, right_region);
    } else {
        // Split the region into three.
        // Left (`region`): [start, addr) with old flags
        // Middle (`middle_region`): [addr, addr + size) with new flags
        // Right (`right_region`): [addr + size, end) with old flags
        struct vm_region* middle_region = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(middle_region))
            return PTR_ERR(middle_region);
        struct vm_region* right_region = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(right_region)) {
            slab_cache_free(&vm_region_cache, middle_region);
            return PTR_ERR(right_region);
        }
        region->end = start;
        vobj_ref(region->vobj);
        *middle_region = (struct vm_region){
            .vm = vm,
            .start = start,
            .end = end,
            .offset = region->offset + offset,
            .flags = masked_set(old_flags, flags, mask),
            .vobj = region->vobj,
        };
        vobj_ref(region->vobj);
        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .offset = region->offset + offset + npages,
            .flags = old_flags,
            .vobj = region->vobj,
        };
        vm_insert_region_after(vm, region, middle_region);
        vm_insert_region_after(vm, middle_region, right_region);
    }

    page_table_unmap(start, npages);

    return 0;
}

int vm_region_free(struct vm_region* region, size_t offset, size_t npages) {
    ASSERT(spinlock_is_locked_by_current(&region->vm->lock));

    if (npages == 0)
        return -EINVAL;

    size_t start = region->start + offset;
    size_t end = start + npages;
    if (start < region->start || region->end < end)
        return -EINVAL;
    if (end <= start)
        return -EOVERFLOW;

    if (region->start == start && end == region->end) {
        // Unmap the whole region
        vm_remove_region(region->vm, region);
        vm_region_destroy(region);
    } else if (region->start == start) {
        // Unmap the beginning of the region.
        // The region is shrunk to [start + size, end)
        region->start += npages;
        region->offset += npages;
    } else if (region->end == end) {
        // Unmap the end of the region.
        // The region is shrunk to [start, end - size)
        region->end -= npages;
    } else {
        // Split the region into two, unmapping the middle part.
        // Left (`region`): [start, addr)
        // Right (`right_region`): [addr + size, end)
        struct vm_region* right_region = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);
        vobj_ref(region->vobj);
        *right_region = (struct vm_region){
            .vm = region->vm,
            .start = end,
            .end = region->end,
            .offset = region->offset + (end - region->start),
            .flags = region->flags,
            .vobj = region->vobj,
        };
        region->end = start;
        vm_insert_region_after(region->vm, region, right_region);
    }

    page_table_unmap(start, npages);

    return 0;
}
