#include "memory.h"
#include "private.h"
#include <common/string.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/lock.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <kernel/task.h>
#include <stdatomic.h>
#include <stdint.h>

static struct slab_cache vm_cache;

struct vm* vm_create(void* start, void* end) {
    if (end <= start || KERNEL_VM_END <= (uintptr_t)start)
        return ERR_PTR(-EINVAL);
    struct vm* vm = slab_cache_alloc(&vm_cache);
    if (IS_ERR(vm))
        return vm;
    struct page_directory* page_directory = page_directory_create();
    if (IS_ERR(page_directory)) {
        slab_cache_free(&vm_cache, vm);
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

void vm_region_set_obj(struct vm_region* region, struct vm_obj* obj,
                       size_t offset) {
    ASSERT(spinlock_is_locked_by_current(&region->vm->lock));
    ASSERT(!region->obj);
    ASSERT(!region->shared_next);
    ASSERT(obj);

    region->offset = offset;

    spinlock_lock(&obj->lock);
    region->obj = obj;
    if (region->flags & VM_SHARED) {
        region->shared_next = obj->shared_regions;
        obj->shared_regions = region;
    }
    spinlock_unlock(&obj->lock);
}

static void vm_region_unset_obj(struct vm_region* region) {
    struct vm_obj* obj = region->obj;
    spinlock_lock(&obj->lock);
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
    spinlock_unlock(&obj->lock);
}

static struct slab_cache region_cache;

static void vm_region_destroy(struct vm_region* region) {
    ASSERT(!region->prev);
    ASSERT(!region->next);
    struct vm_obj* obj = region->obj;
    if (obj) {
        if (region->flags & VM_SHARED)
            vm_region_unset_obj(region);
        vm_obj_unref(obj);
    }
    if (region->flags & VM_SHARED)
        ASSERT(!page_set_first(&region->private_pages));
    page_set_clear(&region->private_pages);
    slab_cache_free(&region_cache, region);
}

void vm_unref(struct vm* vm) {
    if (!vm)
        return;
    ASSERT(vm != kernel_vm);
    ASSERT(vm->ref_count > 0);
    if (--vm->ref_count > 0)
        return;

    ASSERT(vm != current->vm);

    struct vm_region* region = vm->regions;
    while (region) {
        struct vm_region* next = region->next;
        region->prev = region->next = NULL;
        vm_region_destroy(region);
        region = next;
    }

    page_directory_destroy(vm->page_directory);
    slab_cache_free(&vm_cache, vm);
}

struct vm* vm_enter(struct vm* vm) {
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
                                         struct vm_region* region) {
    struct vm_region* cloned = slab_cache_alloc(&region_cache);
    if (IS_ERR(cloned))
        return cloned;

    *cloned = (struct vm_region){
        .vm = new_vm,
        .start = region->start,
        .end = region->end,
        .flags = region->flags,
    };

    struct page* page = page_set_first(&region->private_pages);
    while (page) {
        struct page* new_page =
            page_set_alloc_at(&cloned->private_pages, page->offset);
        if (IS_ERR(new_page)) {
            vm_region_destroy(cloned);
            return ERR_CAST(new_page);
        }
        void* src = kmap_page(page);
        void* dest = kmap_page(new_page);
        memcpy(dest, src, PAGE_SIZE);
        kunmap(dest);
        kunmap(src);
        page = page->next;
    }

    struct vm_obj* obj = region->obj;
    if (obj) {
        vm_obj_ref(obj);
        vm_region_set_obj(cloned, obj, region->offset);
    }

    return cloned;
}

struct vm* vm_clone(struct vm* vm) {
    ASSERT(vm != kernel_vm);

    struct vm* new_vm = slab_cache_alloc(&vm_cache);
    if (IS_ERR(new_vm))
        return new_vm;

    *new_vm = (struct vm){
        .start = vm->start,
        .end = vm->end,
        .ref_count = 1,
    };

    spinlock_lock(&new_vm->lock);
    spinlock_lock(&vm->lock);
    int ret = 0;

    struct page_directory* page_directory = page_directory_create();
    if (IS_ERR(page_directory)) {
        ret = PTR_ERR(page_directory);
        goto fail;
    }
    new_vm->page_directory = page_directory;

    struct vm_region* prev_region = NULL;
    for (struct vm_region* it = vm->regions; it; it = it->next) {
        struct vm_region* region = vm_region_clone(new_vm, it);
        if (IS_ERR(region)) {
            ret = PTR_ERR(region);
            goto fail;
        }
        region->prev = prev_region;
        if (prev_region)
            prev_region->next = region;
        else
            new_vm->regions = region;
        prev_region = region;
    }

fail:
    spinlock_unlock(&vm->lock);
    spinlock_unlock(&new_vm->lock);
    if (IS_ERR(ret)) {
        vm_unref(new_vm);
        return ERR_PTR(ret);
    }
    return new_vm;
}

static bool vm_contains(struct vm* vm, void* virt_addr) {
    size_t index = (uintptr_t)virt_addr / PAGE_SIZE;
    return vm->start <= index && index < vm->end;
}

static struct page* vm_region_handle_page_fault(struct vm_region* region,
                                                size_t offset,
                                                uint32_t error_code) {
    struct vm_obj* obj = region->obj;
    if (!obj)
        return ERR_PTR(-EFAULT);

    if (!(region->flags & VM_SHARED)) {
        struct page* private_page =
            page_set_get(&region->private_pages, offset);
        if (private_page)
            return private_page;
    }

    const struct vm_ops* vm_ops = obj->vm_ops;
    ASSERT(vm_ops);

    int ret = 0;
    spinlock_lock(&obj->lock);

    size_t obj_offset = region->offset + offset;
    struct page* shared_page = page_set_get(&obj->shared_pages, obj_offset);
    if (!shared_page) {
        ASSERT(vm_ops->populate);
        shared_page = vm_ops->populate(obj, obj_offset, error_code);
        if (IS_ERR(shared_page)) {
            ret = PTR_ERR(shared_page);
            goto fail;
        }
    }

    if (!(error_code & X86_PF_WRITE)) {
        spinlock_unlock(&obj->lock);
        return shared_page;
    }

    if (region->flags & VM_SHARED) {
        if (vm_ops->on_write)
            vm_ops->on_write(obj, shared_page);
        spinlock_unlock(&obj->lock);
        return shared_page;
    }

    // Copy on write
    struct page* private_page =
        page_set_alloc_at(&region->private_pages, offset);
    if (IS_ERR(private_page)) {
        ret = PTR_ERR(private_page);
        goto fail;
    }
    void* src = kmap_page(shared_page);
    void* dest = kmap_page(private_page);
    memcpy(dest, src, PAGE_SIZE);
    kunmap(dest);
    kunmap(src);

    spinlock_unlock(&obj->lock);
    return private_page;

fail:
    spinlock_unlock(&obj->lock);
    return ERR_PTR(ret);
}

bool vm_handle_page_fault(void* virt_addr, uint32_t error_code) {
    struct vm* vm;
    if (current && vm_contains(current->vm, virt_addr))
        vm = current->vm;
    else if (!(error_code & X86_PF_USER) && vm_contains(kernel_vm, virt_addr))
        vm = kernel_vm;
    else
        return false;

    spinlock_lock(&vm->lock);
    bool ret = false;

    struct vm_region* region = vm_find(vm, virt_addr);
    if (!region)
        goto fail;
    if (error_code & X86_PF_WRITE) {
        if (!(region->flags & VM_WRITE))
            goto fail;
    } else if (!(region->flags & VM_READ)) {
        goto fail;
    }

    size_t offset = (uintptr_t)virt_addr / PAGE_SIZE - region->start;
    struct page* page = vm_region_handle_page_fault(region, offset, error_code);
    if (IS_ERR(page))
        goto fail;
    int rc = page_table_map(ROUND_DOWN((uintptr_t)virt_addr, PAGE_SIZE),
                            page_to_pfn(page), 1,
                            vm_flags_to_pte_flags(region->flags));
    if (IS_ERR(rc))
        goto fail;

    ret = true;
fail:
    spinlock_unlock(&vm->lock);
    return ret;
}

struct vm_region* vm_find(struct vm* vm, void* virt_addr) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));
    if (!vm_contains(vm, virt_addr))
        return NULL;
    size_t index = (uintptr_t)virt_addr / PAGE_SIZE;
    for (struct vm_region* it = vm->regions; it; it = it->next) {
        ASSERT(it->start < it->end);
        if (it->next)
            ASSERT(it->end <= it->next->start);
        if (it->start > index)
            break;
        if (index < it->end)
            return it;
    }
    return NULL;
}

struct vm_region* vm_find_gap(struct vm* vm, size_t npages, size_t* start) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));

    if (npages == 0)
        return ERR_PTR(-EINVAL);
    if (vm->start + npages <= vm->start)
        return ERR_PTR(-EOVERFLOW);
    if (vm->start + npages > vm->end)
        return ERR_PTR(-ENOMEM);

    if (!vm->regions || vm->start + npages <= vm->regions->start) {
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

void vm_insert_region_after(struct vm* vm, struct vm_region* prev,
                            struct vm_region* inserted) {
    ASSERT(vm == inserted->vm);
    if (prev) {
        ASSERT(prev != inserted);
        ASSERT(vm == prev->vm);
    }
    ASSERT(spinlock_is_locked_by_current(&vm->lock));
    ASSERT(inserted->start < inserted->end);
    ASSERT(!inserted->prev);
    ASSERT(!inserted->next);
    if (prev) {
        ASSERT(prev->end <= inserted->start);
        inserted->prev = prev;
        inserted->next = prev->next;
        if (prev->next) {
            ASSERT(inserted->end <= prev->next->start);
            prev->next->prev = inserted;
        }
        prev->next = inserted;
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

struct vm_region* vm_alloc(struct vm* vm, size_t npages) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));

    if (npages == 0)
        return ERR_PTR(-EINVAL);

    struct vm_region* region = slab_cache_alloc(&region_cache);
    if (IS_ERR(region))
        return ERR_PTR(region);

    size_t start;
    struct vm_region* prev = vm_find_gap(vm, npages, &start);
    if (IS_ERR(prev)) {
        slab_cache_free(&region_cache, region);
        return ERR_CAST(prev);
    }

    *region = (struct vm_region){
        .vm = vm,
        .start = start,
        .end = start + npages,
    };
    vm_insert_region_after(vm, prev, region);

    return region;
}

struct vm_region* vm_alloc_at(struct vm* vm, void* virt_addr, size_t npages) {
    ASSERT(spinlock_is_locked_by_current(&vm->lock));
    ASSERT((uintptr_t)virt_addr % PAGE_SIZE == 0);

    if (npages == 0)
        return ERR_PTR(-EINVAL);

    size_t start = (uintptr_t)virt_addr / PAGE_SIZE;
    size_t end = start + npages;
    if (end <= start)
        return ERR_PTR(-EOVERFLOW);
    if (start < vm->start || vm->end < end)
        return ERR_PTR(-ERANGE);

    struct vm_region* region = slab_cache_alloc(&region_cache);
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
    slab_cache_free(&region_cache, region);
    return ERR_PTR(ret);
}

void* vm_region_to_virt(struct vm_region* region) {
    return (void*)(region->start * PAGE_SIZE);
}

void vm_region_remove(struct vm_region* region) {
    struct vm* vm = region->vm;
    ASSERT(spinlock_is_locked_by_current(&vm->lock));
    if (region->prev)
        region->prev->next = region->next;
    else
        vm->regions = region->next;
    if (region->next)
        region->next->prev = region->prev;
    region->prev = region->next = NULL;
}

int vm_region_resize(struct vm_region* region, size_t new_npages) {
    struct vm* vm = region->vm;
    ASSERT(spinlock_is_locked_by_current(&vm->lock));

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
        page_table_unmap(new_end * PAGE_SIZE, old_npages - new_npages);
        region->end = new_end;
        return 0;
    }

    // If there is enough space after the region, we can simply extend the
    // region
    size_t next_start = region->next ? region->next->start : vm->end;
    if (new_end <= next_start) {
        region->end = new_end;
        return 0;
    }

    // Otherwise, we need to allocate a new range
    size_t new_start;
    struct vm_region* prev = vm_find_gap(vm, new_npages, &new_start);
    if (IS_ERR(prev))
        return PTR_ERR(prev);

    // Unmap the old range
    page_table_unmap(region->start * PAGE_SIZE, old_npages);
    vm_region_remove(region);

    region->start = new_start;
    region->end = new_start + new_npages;
    vm_insert_region_after(vm, prev, region);

    return 0;
}

int vm_region_set_flags(struct vm_region* region, size_t offset, size_t npages,
                        unsigned flags, unsigned mask) {
    struct vm* vm = region->vm;
    ASSERT(spinlock_is_locked_by_current(&vm->lock));

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

        struct vm_region* right_region = slab_cache_alloc(&region_cache);
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);

        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .flags = region->flags,
        };
        region->end = end;
        region->flags = new_flags;

        vm_insert_region_after(vm, region, right_region);

        if (region->obj) {
            vm_obj_ref(region->obj);
            vm_region_set_obj(right_region, region->obj,
                              region->offset + npages);
        }
    } else if (end == region->end) {
        // Split the region into two.
        // Left (`region`): [region->start, start) with old flags
        // Right (`right_region`): [start, end) with new flags

        struct vm_region* right_region = slab_cache_alloc(&region_cache);
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);

        *right_region = (struct vm_region){
            .vm = vm,
            .start = start,
            .end = end,
            .flags = new_flags,
        };
        region->end = start;

        vm_insert_region_after(vm, region, right_region);

        if (region->obj) {
            vm_obj_ref(region->obj);
            vm_region_set_obj(right_region, region->obj,
                              region->offset + offset);
        }
    } else {
        // Split the region into three.
        // Left (`region`): [region->start, start) with old flags
        // Middle (`middle_region`): [start, end) with new flags
        // Right (`right_region`): [end, region->end) with old flags

        struct vm_region* middle_region = slab_cache_alloc(&region_cache);
        if (IS_ERR(middle_region))
            return PTR_ERR(middle_region);
        struct vm_region* right_region = slab_cache_alloc(&region_cache);
        if (IS_ERR(right_region)) {
            slab_cache_free(&region_cache, middle_region);
            return PTR_ERR(right_region);
        }

        *middle_region = (struct vm_region){
            .vm = vm,
            .start = start,
            .end = end,
            .flags = new_flags,
        };
        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .flags = region->flags,
        };
        region->end = start;

        vm_insert_region_after(vm, region, middle_region);
        vm_insert_region_after(vm, middle_region, right_region);

        if (region->obj) {
            vm_obj_ref(region->obj);
            vm_region_set_obj(middle_region, region->obj,
                              region->offset + offset);
            vm_obj_ref(region->obj);
            vm_region_set_obj(right_region, region->obj,
                              region->offset + offset + npages);
        }
    }

    page_table_unmap(start * PAGE_SIZE, npages);

    return 0;
}

int vm_region_free(struct vm_region* region, size_t offset, size_t npages) {
    struct vm* vm = region->vm;
    ASSERT(spinlock_is_locked_by_current(&vm->lock));

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
    } else if (region->end == end) {
        // Unmap the end of the region.
        // The region is shrunk to [region->start, start)
        region->end -= npages;
    } else {
        // Split the region into two, unmapping the middle part.
        // Left (`region`): [region->start, start)
        // Right (`right_region`): [end, region->end)

        struct vm_region* right_region = slab_cache_alloc(&region_cache);
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);

        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .flags = region->flags,
        };
        region->end = start;

        vm_insert_region_after(vm, region, right_region);

        if (region->obj) {
            vm_obj_ref(region->obj);
            vm_region_set_obj(right_region, region->obj,
                              region->offset + offset + npages);
        }
    }

    page_table_unmap(start * PAGE_SIZE, npages);

    return 0;
}

struct vm* kernel_vm;

void vm_init(uintptr_t kernel_vm_start) {
    static struct vm vm;
    kernel_vm = &vm;

    size_t start = DIV_CEIL(kernel_vm_start, PAGE_SIZE);
    size_t end = KERNEL_VM_END / PAGE_SIZE;
    ASSERT(start < end);
    vm = (struct vm){
        .start = start,
        .end = end,
        .page_directory = kernel_page_directory,
        .ref_count = 1,
    };

    slab_cache_init(&vm_cache, sizeof(struct vm));
    slab_cache_init(&region_cache, sizeof(struct vm_region));
}
