#include "memory.h"
#include <common/extra.h>
#include <kernel/boot_defs.h>
#include <kernel/kprintf.h>
#include <kernel/panic.h>

struct range {
    size_t size;
    struct range* next;
};

int range_allocator_init(range_allocator* allocator, uintptr_t start,
                         uintptr_t end) {
    ASSERT(start % PAGE_SIZE == 0);
    ASSERT(end % PAGE_SIZE == 0);

    *allocator = (range_allocator){0};
    allocator->start = start;
    allocator->end = end;

    int rc = paging_map_to_free_pages(start, sizeof(struct range), PAGE_WRITE);
    if (IS_ERR(rc))
        return rc;

    struct range* range = (struct range*)start;
    allocator->ranges = range;
    range->size = end - start;
    range->next = NULL;
    return 0;
}

uintptr_t range_allocator_alloc(range_allocator* allocator, size_t size) {
    ASSERT(allocator->ranges);
    size = round_up(size, PAGE_SIZE);
    if (size > allocator->end - allocator->start)
        return -EINVAL;

    mutex_lock(&allocator->lock);

    struct range* prev = NULL;
    struct range* it = allocator->ranges;
    while (it && it->size < size) {
        prev = it;
        it = it->next;
    }
    if (!it) {
        kprintf("Out of virtual address space (0x%x - 0x%x)\n",
                allocator->start, allocator->end);
        mutex_unlock(&allocator->lock);
        return -ENOMEM;
    }

    if (it->size == size) {
        if (prev) {
            prev->next = it->next;
        } else {
            ASSERT(allocator->ranges == it);
            allocator->ranges = it->next;
        }
        paging_kernel_unmap((uintptr_t)it, sizeof(struct range));
        mutex_unlock(&allocator->lock);
        return (uintptr_t)it;
    }

    uintptr_t addr = (uintptr_t)it + size;
    int rc = paging_shallow_copy(addr, (uintptr_t)it, sizeof(struct range),
                                 PAGE_WRITE);
    if (IS_ERR(rc)) {
        mutex_unlock(&allocator->lock);
        return rc;
    }
    struct range* range = (struct range*)addr;
    range->size -= size;
    paging_kernel_unmap((uintptr_t)it, sizeof(struct range));
    if (prev) {
        prev->next = range;
    } else {
        ASSERT(allocator->ranges == it);
        allocator->ranges = range;
    }

    mutex_unlock(&allocator->lock);
    return (uintptr_t)it;
}

int range_allocator_free(range_allocator* allocator, uintptr_t addr,
                         size_t size) {
    ASSERT(addr % PAGE_SIZE == 0);
    ASSERT(allocator->ranges);
    size = round_up(size, PAGE_SIZE);
    if (size > allocator->end - allocator->start)
        return -EINVAL;
    if (addr < allocator->start || allocator->end < addr + size)
        return -EINVAL;

    mutex_lock(&allocator->lock);

    struct range* prev = NULL;
    struct range* it = allocator->ranges;
    while (it && (uintptr_t)it + it->size <= addr) {
        prev = it;
        it = it->next;
    }

    if ((prev && addr < (uintptr_t)prev + prev->size) ||
        (it && (uintptr_t)it < addr + size)) {
        // this range has not been allocated or has been already freed
        mutex_unlock(&allocator->lock);
        return -EINVAL;
    }

    if (prev && (uintptr_t)prev + prev->size == addr) {
        prev->size += size;
        if (it && (uintptr_t)prev + prev->size == (uintptr_t)it) {
            // we're filling a gap
            prev->size += it->size;
            prev->next = it->next;
            paging_kernel_unmap((uintptr_t)it, sizeof(struct range));
        }
        mutex_unlock(&allocator->lock);
        return 0;
    }
    if (it && (uintptr_t)it == addr + size) {
        int rc = paging_shallow_copy(addr, (uintptr_t)it, sizeof(struct range),
                                     PAGE_WRITE);
        if (IS_ERR(rc)) {
            mutex_unlock(&allocator->lock);
            return rc;
        }
        struct range* range = (struct range*)addr;
        range->size += size;
        paging_kernel_unmap((uintptr_t)it, sizeof(struct range));
        if (prev) {
            prev->next = range;
        } else {
            ASSERT(allocator->ranges == it);
            allocator->ranges = range;
        }
        mutex_unlock(&allocator->lock);
        return 0;
    }

    int rc = paging_map_to_free_pages(addr, sizeof(struct range), PAGE_WRITE);
    if (IS_ERR(rc)) {
        mutex_unlock(&allocator->lock);
        return rc;
    }

    struct range* range = (struct range*)addr;
    range->size = size;
    range->next = it;
    if (prev)
        prev->next = range;
    else
        allocator->ranges = range;

    mutex_unlock(&allocator->lock);
    return 0;
}
