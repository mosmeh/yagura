#include "memory.h"
#include "memory_private.h"
#include <common/string.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/process.h>

struct vm* kernel_vm;

static struct slab_cache vm_region_cache;

void vm_init(void) {
    static struct vm vm;
    kernel_vm = &vm;
    vm = (struct vm){
        .start = KERNEL_HEAP_START,
        .end = KERNEL_HEAP_END,
        .page_directory = kernel_page_directory,
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
        .start = (uintptr_t)start,
        .end = (uintptr_t)end,
        .page_directory = page_directory,
    };
    return vm;
}

void vm_destroy(struct vm* vm) {
    if (!vm)
        return;

    ASSERT(current);
    ASSERT(vm != kernel_vm);

    struct vm* saved_vm = current->vm;
    if (vm != saved_vm)
        vm_enter(vm);
    ASSERT(current->vm == vm);

    struct vm_region* region = vm->regions;
    while (region) {
        struct vm_region* next = region->next;
        slab_cache_free(&vm_region_cache, region);
        region = next;
    }

    page_directory_destroy_current();

    // We have to switch to another vm before the current vm is freed.
    // If we are destroying the vm that was previously active, switch to
    // kernel_vm. Otherwise, switch back to the previously active vm.
    vm_enter(vm == saved_vm ? kernel_vm : saved_vm);

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

    mutex_lock(&vm->lock);

    struct page_directory* page_directory = page_directory_clone_current();
    if (IS_ERR(page_directory)) {
        mutex_unlock(&vm->lock);
        kfree(new_vm);
        return ERR_CAST(page_directory);
    }

    *new_vm = (struct vm){
        .start = vm->start,
        .end = vm->end,
        .page_directory = page_directory,
    };

    struct vm_region* it = vm->regions;
    struct vm_region* prev_cloned = NULL;
    while (it) {
        struct vm_region* cloned = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(cloned)) {
            mutex_unlock(&vm->lock);
            vm_destroy(new_vm);
            return ERR_CAST(cloned);
        }
        *cloned = *it;

        cloned->prev = prev_cloned;
        cloned->next = NULL;
        if (prev_cloned)
            prev_cloned->next = cloned;
        else
            new_vm->regions = cloned;
        prev_cloned = cloned;

        it = it->next;
    }

    mutex_unlock(&vm->lock);
    return new_vm;
}

struct vm_region* vm_find_region(struct vm* vm, void* virt_addr) {
    uintptr_t addr = (uintptr_t)virt_addr;
    struct vm_region* it = vm->regions;
    while (it) {
        if (it->next)
            ASSERT(it->end <= it->next->start);
        if (it->start <= addr && addr < it->end)
            return it;
        it = it->next;
    }
    return NULL;
}

struct vm_region* vm_find_gap(struct vm* vm, size_t size,
                              uintptr_t* virt_addr) {
    if (vm->start + size > vm->end)
        return ERR_PTR(-ENOMEM);
    if (!vm->regions) {
        if (virt_addr)
            *virt_addr = vm->start;
        return NULL;
    }

    struct vm_region* prev = NULL;
    struct vm_region* it = vm->regions;
    while (it) {
        if (it->next)
            ASSERT(it->end <= it->next->start);
        if (prev && prev->end + size <= it->start) {
            if (virt_addr)
                *virt_addr = prev->end;
            return prev;
        }
        prev = it;
        it = it->next;
    }
    if (prev && prev->end + size <= vm->end) {
        if (virt_addr)
            *virt_addr = prev->end;
        return prev;
    }

    kprint("vm: out of virtual memory\n");
    return ERR_PTR(-ENOMEM);
}

void vm_insert_region_after(struct vm* vm, struct vm_region* cursor,
                            struct vm_region* inserted) {
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
    if (region->prev)
        region->prev->next = region->next;
    else
        vm->regions = region->next;
    if (region->next)
        region->next->prev = region->prev;
    region->prev = region->next = NULL;
}

static struct vm* vm_for_flags(int vm_flags) {
    if (!(vm_flags & VM_USER))
        return kernel_vm;
    ASSERT(current);
    ASSERT(current->vm != kernel_vm);
    return current->vm;
}

static struct vm* vm_for_addr(void* addr) {
    ASSERT(addr);
    if (is_kernel_address(addr))
        return kernel_vm;
    ASSERT(current);
    ASSERT(current->vm != kernel_vm);
    return current->vm;
}

static int validate_range(uintptr_t start, size_t size) {
    if (!start)
        return -EFAULT;
    if (size == 0)
        return -EINVAL;
    if (start + size < start)
        return -EINVAL;
    return 0;
}

static bool validate_vm_flags(int vm_flags) {
    if ((vm_flags & VM_USER) && (!current || current->vm == kernel_vm)) {
        // kernel_vm does not have user address range
        return false;
    }
    if ((vm_flags & VM_WRITE) && !(vm_flags & VM_READ)) {
        // Write-only mapping is not possible with x86 paging
        return false;
    }
    if ((vm_flags & VM_SHARED) && !(vm_flags & VM_RW)) {
        // Regions without actual mapping cannot be shared
        return false;
    }
    return true;
}

// Translate VM_* flags to PTE_* flags
static uint16_t to_pte_flags(int vm_flags) {
    ASSERT(validate_vm_flags(vm_flags));

    uint16_t pte_flags = (vm_flags & VM_USER) ? PTE_USER : PTE_GLOBAL;
    if (vm_flags & VM_WRITE)
        pte_flags |= PTE_WRITE;
    if (vm_flags & VM_SHARED)
        pte_flags |= PTE_SHARED;
    if (vm_flags & VM_WC)
        pte_flags |= PTE_PAT;
    return pte_flags;
}

static void* alloc(struct vm* vm, size_t size, int vm_flags) {
    struct vm_region* region = slab_cache_alloc(&vm_region_cache);
    if (IS_ERR(region))
        return ERR_PTR(region);

    int ret = 0;

    uintptr_t virt_addr;
    struct vm_region* cursor = vm_find_gap(vm, size, &virt_addr);
    if (IS_ERR(cursor)) {
        ret = PTR_ERR(cursor);
        goto fail;
    }

    if (vm_flags & VM_RW) {
        ret = page_table_map_anon(virt_addr, size, to_pte_flags(vm_flags));
        if (IS_ERR(ret))
            goto fail;
    }

    region->start = virt_addr;
    region->end = virt_addr + size;
    region->flags = vm_flags;
    vm_insert_region_after(vm, cursor, region);

    return (void*)virt_addr;

fail:
    slab_cache_free(&vm_region_cache, region);
    return ERR_PTR(ret);
}

static void* alloc_at(struct vm* vm, uintptr_t virt_addr, size_t size,
                      int vm_flags) {
    struct vm_region* region = slab_cache_alloc(&vm_region_cache);
    if (IS_ERR(region))
        return ERR_PTR(region);

    int ret = 0;

    // Check if the range is already occupied
    struct vm_region* prev = NULL;
    struct vm_region* it = vm->regions;
    while (it && it->start < virt_addr) {
        if (it->end > virt_addr) {
            ret = -EEXIST;
            goto fail;
        }
        prev = it;
        it = it->next;
    }
    if (prev && prev->end > virt_addr && prev->start < virt_addr + size) {
        ret = -EEXIST;
        goto fail;
    }

    if (vm_flags & VM_RW) {
        ret = page_table_map_anon(virt_addr, size, to_pte_flags(vm_flags));
        if (IS_ERR(ret))
            goto fail;
    }

    region->start = virt_addr;
    region->end = virt_addr + size;
    region->flags = vm_flags;
    vm_insert_region_after(vm, prev, region);

    return (void*)virt_addr;

fail:
    slab_cache_free(&vm_region_cache, region);
    return ERR_PTR(ret);
}

static int set_flags(struct vm* vm, void* addr, size_t size, int vm_flags) {
    struct vm_region* region = vm_find_region(vm, addr);
    if (!region)
        return -ENOENT;
    if (region->end < (uintptr_t)addr + size)
        return -EINVAL;
    if (region->flags == vm_flags)
        return 0;
    if (!(region->flags & VM_RW) && (vm_flags & VM_RW))
        return -EINVAL;

    int old_flags = region->flags;
    if (region->start == (uintptr_t)addr &&
        region->start + size == region->end) {
        // Modify the whole region
        region->flags = vm_flags;
    } else if (region->start == (uintptr_t)addr) {
        // Split the region into two.
        // Left (`region`): [start, start + size) with new flags
        // Right (`right_region`): [start + size, end) with old flags
        struct vm_region* right_region = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);
        right_region->start = region->start + size;
        right_region->end = region->end;
        right_region->flags = region->flags;
        region->end = region->start + size;
        region->flags = vm_flags;
        vm_insert_region_after(vm, region, right_region);
    } else if (region->end == (uintptr_t)addr + size) {
        // Split the region into two.
        // Left (`region`): [start, addr) with old flags
        // Right (`right_region`): [addr, end) with new flags
        struct vm_region* right_region = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);
        right_region->start = (uintptr_t)addr;
        right_region->end = region->end;
        right_region->flags = vm_flags;
        region->end = (uintptr_t)addr;
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
        middle_region->start = (uintptr_t)addr;
        middle_region->end = middle_region->start + size;
        middle_region->flags = vm_flags;
        right_region->start = middle_region->end;
        right_region->end = region->end;
        right_region->flags = region->flags;
        region->end = middle_region->start;
        vm_insert_region_after(vm, region, middle_region);
        vm_insert_region_after(vm, middle_region, right_region);
    }

    if ((old_flags & VM_RW) && !(vm_flags & VM_RW))
        page_table_unmap((uintptr_t)addr, size);
    else
        page_table_set_flags((uintptr_t)addr, size, to_pte_flags(vm_flags));

    return 0;
}

static void* phys_map(struct vm* vm, uintptr_t phys_addr, size_t size,
                      int vm_flags) {
    struct vm_region* region = slab_cache_alloc(&vm_region_cache);
    if (IS_ERR(region))
        return ERR_PTR(region);

    int ret = 0;

    uintptr_t virt_addr;
    struct vm_region* cursor = vm_find_gap(vm, size, &virt_addr);
    if (IS_ERR(cursor)) {
        ret = PTR_ERR(cursor);
        goto fail;
    }

    if (vm_flags & VM_RW) {
        ret = page_table_map_phys(virt_addr, phys_addr, size,
                                  to_pte_flags(vm_flags));
        if (IS_ERR(ret))
            goto fail;
    }

    region->start = virt_addr;
    region->end = virt_addr + size;
    region->flags = vm_flags;
    vm_insert_region_after(vm, cursor, region);

    return (void*)virt_addr;

fail:
    slab_cache_free(&vm_region_cache, region);
    return ERR_PTR(ret);
}

static void* virt_map(struct vm* vm, void* src_virt_addr, size_t size,
                      int vm_flags) {
    if (!(vm_flags & VM_SHARED)) {
        void* dest_virt_addr = alloc(vm, size, vm_flags | VM_WRITE);
        if (IS_ERR(dest_virt_addr))
            return dest_virt_addr;
        memcpy(dest_virt_addr, src_virt_addr, size);
        if (!(vm_flags & VM_WRITE))
            set_flags(vm, dest_virt_addr, size, vm_flags);
        return dest_virt_addr;
    }

    ASSERT(vm_flags & VM_RW);

    struct vm_region* region = slab_cache_alloc(&vm_region_cache);
    if (IS_ERR(region))
        return ERR_PTR(region);

    int ret = 0;

    uintptr_t dest_virt_addr;
    struct vm_region* cursor = vm_find_gap(vm, size, &dest_virt_addr);
    if (IS_ERR(cursor)) {
        ret = PTR_ERR(cursor);
        goto fail;
    }

    ret = page_table_shallow_copy(dest_virt_addr, (uintptr_t)src_virt_addr,
                                  size, to_pte_flags(vm_flags));
    if (IS_ERR(ret))
        goto fail;

    region->start = dest_virt_addr;
    region->end = dest_virt_addr + size;
    region->flags = vm_flags;
    vm_insert_region_after(vm, cursor, region);

    return (void*)dest_virt_addr;

fail:
    slab_cache_free(&vm_region_cache, region);
    return ERR_PTR(-ENOMEM);
}

static void* resize(struct vm* vm, void* virt_addr, size_t new_size) {
    struct vm_region* region = vm_find_region(vm, virt_addr);
    if (!region)
        return ERR_PTR(-ENOENT);
    if ((uintptr_t)virt_addr != region->start)
        return ERR_PTR(-EINVAL);
    if (region->start + new_size == region->end)
        return virt_addr;

    size_t old_size = region->end - region->start;

    // Shrink the region
    if (new_size < old_size) {
        page_table_unmap(region->start + new_size, old_size - new_size);
        region->end = region->start + new_size;
        return virt_addr;
    }

    uint16_t pte_flags = to_pte_flags(region->flags);

    // If the region is the last one or there is enough space after the
    // region, we can simply extend the region
    if (!region->next || region->start + new_size < region->next->start) {
        if (region->flags & VM_RW) {
            int rc = page_table_map_anon(region->start + old_size,
                                         new_size - old_size, pte_flags);
            if (IS_ERR(rc))
                return ERR_PTR(rc);
        }
        region->end = region->start + new_size;
        return virt_addr;
    }

    // Otherwise, we need to allocate a new range and copy the mapping

    uintptr_t new_virt_addr;
    struct vm_region* cursor = vm_find_gap(vm, new_size, &new_virt_addr);
    if (IS_ERR(cursor))
        return ERR_PTR(cursor);

    // Copy
    int rc = page_table_shallow_copy(new_virt_addr, region->start, old_size,
                                     pte_flags);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    // Extend
    if (region->flags & VM_RW) {
        rc = page_table_map_anon(new_virt_addr + old_size, new_size - old_size,
                                 pte_flags);
        if (IS_ERR(rc)) {
            page_table_unmap(new_virt_addr, old_size);
            return ERR_PTR(rc);
        }
    }

    // Unmap the old range
    page_table_unmap(region->start, old_size);

    region->start = new_virt_addr;
    region->end = new_virt_addr + new_size;

    vm_remove_region(vm, region);
    vm_insert_region_after(vm, cursor, region);

    return (void*)new_virt_addr;
}

static int unmap(struct vm* vm, void* virt_addr, size_t size) {
    struct vm_region* region = vm_find_region(vm, virt_addr);
    if (!region)
        return -ENOENT;

    uintptr_t addr = (uintptr_t)virt_addr;
    if (region->end < addr + size)
        return -EINVAL;

    if (region->start == addr && region->start + size == region->end) {
        // Unmap the whole region
        page_table_unmap(addr, size);
        vm_remove_region(vm, region);
        slab_cache_free(&vm_region_cache, region);
    } else if (region->start == addr) {
        // Unmap the beginning of the region.
        // The region is shrunk to [start + size, end)
        page_table_unmap(addr, size);
        region->start += size;
    } else if (region->end == addr + size) {
        // Unmap the end of the region.
        // The region is shrunk to [start, end - size)
        page_table_unmap(addr, size);
        region->end -= size;
    } else {
        // Split the region into two, unmapping the middle part.
        // Left (`region`): [start, addr)
        // Right (`right_region`): [addr + size, end)
        struct vm_region* right_region = slab_cache_alloc(&vm_region_cache);
        if (IS_ERR(right_region))
            return PTR_ERR(right_region);
        page_table_unmap(addr, size);
        right_region->start = addr + size;
        right_region->end = region->end;
        right_region->flags = region->flags;
        region->end = addr;
        vm_insert_region_after(vm, region, right_region);
    }

    return 0;
}

// Aligns the range to the page boundary.  The aligned range encompasses the
// original range.
// Returns the aligned start address. The size is updated to the aligned size.
static uintptr_t page_align_range(uintptr_t start, size_t* size) {
    uintptr_t aligned_start = round_down(start, PAGE_SIZE);
    uintptr_t aligned_end = round_up(start + *size, PAGE_SIZE);
    *size = aligned_end - aligned_start;
    return aligned_start;
}

void* vm_alloc(size_t size, int vm_flags) {
    if (size == 0)
        return ERR_PTR(-EINVAL);
    if (!validate_vm_flags(vm_flags))
        return ERR_PTR(-EINVAL);
    size = round_up(size, PAGE_SIZE);

    struct vm* vm = vm_for_flags(vm_flags);
    mutex_lock(&vm->lock);
    void* addr = alloc(vm, size, vm_flags);
    mutex_unlock(&vm->lock);
    return addr;
}

void* vm_alloc_at(void* virt_addr, size_t size, int vm_flags) {
    int rc = validate_range((uintptr_t)virt_addr, size);
    if (IS_ERR(rc))
        return ERR_PTR(rc);
    if (!validate_vm_flags(vm_flags))
        return ERR_PTR(-EINVAL);
    if (is_user_address(virt_addr) && !(vm_flags & VM_USER))
        return false;

    uintptr_t aligned_addr = page_align_range((uintptr_t)virt_addr, &size);
    struct vm* vm = vm_for_flags(vm_flags);
    if (aligned_addr < vm->start || vm->end < aligned_addr + size)
        return ERR_PTR(-ERANGE);

    mutex_lock(&vm->lock);
    unsigned char* addr = alloc_at(vm, aligned_addr, size, vm_flags);
    mutex_unlock(&vm->lock);
    if (IS_ERR(addr))
        return addr;
    return addr + ((uintptr_t)virt_addr - aligned_addr);
}

void* vm_phys_map(uintptr_t phys_addr, size_t size, int vm_flags) {
    int rc = validate_range(phys_addr, size);
    if (IS_ERR(rc))
        return ERR_PTR(rc);
    if (!validate_vm_flags(vm_flags))
        return ERR_PTR(-EINVAL);

    uintptr_t aligned_addr = page_align_range(phys_addr, &size);
    struct vm* vm = vm_for_flags(vm_flags);
    mutex_lock(&vm->lock);
    unsigned char* addr = phys_map(vm, aligned_addr, size, vm_flags);
    mutex_unlock(&vm->lock);
    if (IS_ERR(addr))
        return addr;
    return addr + (phys_addr - aligned_addr);
}

void* vm_virt_map(void* virt_addr, size_t size, int vm_flags) {
    int rc = validate_range((uintptr_t)virt_addr, size);
    if (IS_ERR(rc))
        return ERR_PTR(rc);
    if (!validate_vm_flags(vm_flags))
        return ERR_PTR(-EINVAL);
    if (is_user_address(virt_addr) && !(vm_flags & VM_USER))
        return ERR_PTR(-EINVAL);

    uintptr_t aligned_addr = page_align_range((uintptr_t)virt_addr, &size);
    struct vm* vm = vm_for_flags(vm_flags);
    mutex_lock(&vm->lock);
    unsigned char* addr = virt_map(vm, (void*)aligned_addr, size, vm_flags);
    mutex_unlock(&vm->lock);
    if (IS_ERR(addr))
        return addr;
    return addr + ((uintptr_t)virt_addr - aligned_addr);
}

void* vm_resize(void* virt_addr, size_t new_size) {
    int rc = validate_range((uintptr_t)virt_addr, new_size);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    uintptr_t aligned_addr = page_align_range((uintptr_t)virt_addr, &new_size);
    struct vm* vm = vm_for_addr(virt_addr);
    mutex_lock(&vm->lock);
    unsigned char* new_addr = resize(vm, (void*)aligned_addr, new_size);
    mutex_unlock(&vm->lock);
    if (IS_ERR(new_addr))
        return new_addr;
    return new_addr + ((uintptr_t)virt_addr - aligned_addr);
}

int vm_set_flags(void* addr, size_t size, int vm_flags) {
    int rc = validate_range((uintptr_t)addr, size);
    if (IS_ERR(rc))
        return rc;
    if (!validate_vm_flags(vm_flags))
        return -EINVAL;

    uintptr_t aligned_addr = page_align_range((uintptr_t)addr, &size);
    struct vm* vm = vm_for_addr(addr);
    mutex_lock(&vm->lock);
    rc = set_flags(vm, (void*)aligned_addr, size, vm_flags);
    mutex_unlock(&vm->lock);
    return rc;
}

int vm_unmap(void* addr, size_t size) {
    int rc = validate_range((uintptr_t)addr, size);
    if (IS_ERR(rc))
        return rc;

    uintptr_t aligned_addr = page_align_range((uintptr_t)addr, &size);
    struct vm* vm = vm_for_addr(addr);
    mutex_lock(&vm->lock);
    rc = unmap(vm, (void*)aligned_addr, size);
    mutex_unlock(&vm->lock);
    return rc;
}

int vm_free(void* addr) {
    if (!addr)
        return -EFAULT;

    struct vm* vm = vm_for_addr(addr);
    mutex_lock(&vm->lock);
    struct vm_region* region = vm_find_region(vm, addr);
    if (!region) {
        mutex_unlock(&vm->lock);
        return -ENOENT;
    }
    if (region->start != round_down((uintptr_t)addr, PAGE_SIZE)) {
        mutex_unlock(&vm->lock);
        return -EINVAL;
    }
    page_table_unmap(region->start, region->end - region->start);
    vm_remove_region(vm, region);
    mutex_unlock(&vm->lock);
    slab_cache_free(&vm_region_cache, region);
    return 0;
}
