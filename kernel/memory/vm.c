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

static struct slab_cache region_cache;

static void vm_region_destroy(struct vm_region* region) {
    ASSERT(!region->prev);
    ASSERT(!region->next);
    struct vobj* vobj = region->vobj;
    if (vobj) {
        spinlock_lock(&vobj->lock);
        vobj_remove_region(vobj, region);
        spinlock_unlock(&vobj->lock);
        vobj_unref(vobj);
    }
    slab_cache_free(&region_cache, region);
}

struct vm* kernel_vm;
static struct slab_cache vm_cache;

void vm_init(size_t kernel_heap_start) {
    static struct vm vm;
    kernel_vm = &vm;

    size_t end = KERNEL_HEAP_END / PAGE_SIZE;
    ASSERT(kernel_heap_start < end);
    vm = (struct vm){
        .start = kernel_heap_start,
        .end = end,
        .page_directory = kernel_page_directory,
        .ref_count = 1,
    };

    slab_cache_init(&vm_cache, sizeof(struct vm));
    slab_cache_init(&region_cache, sizeof(struct vm_region));
}

struct vm* vm_create(void* start, void* end) {
    if (end <= start || KERNEL_HEAP_END <= (uintptr_t)start)
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

    struct vm_region* prev_cloned = NULL;
    for (struct vm_region* it = vm->regions; it; it = it->next) {
        struct vm_region* cloned = slab_cache_alloc(&region_cache);
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
        if (vobj) {
            if (it->flags & VM_SHARED) {
                vobj_ref(vobj);
            } else {
                vobj = vobj_clone(vobj);
                if (IS_ERR(vobj)) {
                    ret = PTR_ERR(vobj);
                    slab_cache_free(&region_cache, cloned);
                    goto fail;
                }
            }
            vm_region_set_vobj(cloned, vobj, it->offset);
        }

        if (prev_cloned)
            prev_cloned->next = cloned;
        else
            new_vm->regions = cloned;
        prev_cloned = cloned;
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

bool vm_handle_page_fault(uintptr_t addr, uint32_t error_code) {
    struct vm* vm;
    if (current && vm_contains(current->vm, (void*)addr))
        vm = current->vm;
    else if (!(error_code & X86_PF_USER) && vm_contains(kernel_vm, (void*)addr))
        vm = kernel_vm;
    else
        return false;

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

    size_t offset = addr / PAGE_SIZE - region->start;
    spinlock_lock(&vobj->lock);
    ASSERT(vobj->vm_ops->handle_fault);
    ret = vobj->vm_ops->handle_fault(region, offset, error_code);
    spinlock_unlock(&vobj->lock);
    if (!ret)
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

void vm_region_set_vobj(struct vm_region* region, struct vobj* vobj,
                        size_t offset) {
    ASSERT(spinlock_is_locked_by_current(&region->vm->lock));
    ASSERT(!region->vobj);
    ASSERT(!region->shared_next);
    ASSERT(vobj);

    region->offset = offset;

    spinlock_lock(&vobj->lock);
    region->vobj = vobj;
    region->shared_next = vobj->regions;
    vobj->regions = region;
    spinlock_unlock(&vobj->lock);
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
    ASSERT(spinlock_is_locked_by_current(&region->vm->lock));

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
        page_table_unmap(new_end, old_npages - new_npages);
        region->end = new_end;
        return 0;
    }

    struct vm* vm = region->vm;

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
    page_table_unmap(region->start, old_npages);
    vm_region_remove(region);

    region->start = new_start;
    region->end = new_start + new_npages;
    vm_insert_region_after(vm, prev, region);

    return 0;
}

static unsigned masked_set(unsigned old, unsigned new, unsigned mask) {
    return (~mask & old) | (mask & new);
}

int vm_region_set_flags(struct vm_region* region, size_t offset, size_t npages,
                        unsigned flags, unsigned mask) {
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
    if (start < region->start || end <= start)
        return -EOVERFLOW;
    if (region->end < end)
        return -EINVAL;

    if (region->flags == flags)
        return 0;

    struct vm* vm = region->vm;
    if (offset == 0 && end == region->end) {
        // Modify the whole region
        region->flags = masked_set(region->flags, flags, mask);
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
        region->flags = masked_set(region->flags, flags, mask);

        vm_insert_region_after(vm, region, right_region);

        if (region->vobj) {
            vobj_ref(region->vobj);
            vm_region_set_vobj(right_region, region->vobj,
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
            .flags = masked_set(region->flags, flags, mask),
        };
        region->end = start;

        vm_insert_region_after(vm, region, right_region);

        if (region->vobj) {
            vobj_ref(region->vobj);
            vm_region_set_vobj(right_region, region->vobj,
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
            .flags = masked_set(region->flags, flags, mask),
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

        if (region->vobj) {
            vobj_ref(region->vobj);
            vm_region_set_vobj(middle_region, region->vobj,
                               region->offset + offset);
            vobj_ref(region->vobj);
            vm_region_set_vobj(right_region, region->vobj,
                               region->offset + offset + npages);
        }
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

        struct vm* vm = region->vm;
        *right_region = (struct vm_region){
            .vm = vm,
            .start = end,
            .end = region->end,
            .flags = region->flags,
        };
        region->end = start;

        vm_insert_region_after(vm, region, right_region);

        if (region->vobj) {
            vobj_ref(region->vobj);
            vm_region_set_vobj(right_region, region->vobj,
                               region->offset + offset + npages);
        }
    }

    page_table_unmap(start, npages);

    return 0;
}
