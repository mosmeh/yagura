#include "memory.h"
#include <common/extra.h>
#include <kernel/boot_defs.h>
#include <kernel/panic.h>

struct range {
    uintptr_t base;
    size_t size;
    struct range* next;
};

int range_allocator_init(range_allocator* allocator, uintptr_t start,
                         uintptr_t end) {
    ASSERT(start % PAGE_SIZE == 0);
    ASSERT(end % PAGE_SIZE == 0);
    allocator->start = start;
    allocator->end = end;
    struct range* range = kmalloc(sizeof(struct range));
    if (!range)
        return -ENOMEM;
    allocator->ranges = range;
    range->base = start;
    range->size = end - start;
    return 0;
}

void range_allocator_destroy(range_allocator* allocator) {
    ASSERT(allocator->ranges);
    struct range* it = allocator->ranges;
    while (it) {
        struct range* next = it->next;
        kfree(it);
        it = next;
    }
}

uintptr_t range_allocator_alloc(range_allocator* allocator, size_t size) {
    ASSERT(allocator->ranges);
    size = round_up(size, PAGE_SIZE);

    struct range* prev = NULL;
    struct range* it = allocator->ranges;
    while (it && it->size < size) {
        prev = it;
        it = it->next;
    }
    if (it) {
        uintptr_t base = it->base;
        if (it->size == size) {
            if (prev) {
                prev->next = it->next;
            } else {
                ASSERT(allocator->ranges == it);
                allocator->ranges = it->next;
            }
            kfree(it);
        } else {
            it->base += size;
            it->size -= size;
        }
        return base;
    }

    return -ENOMEM;
}

int range_allocator_free(range_allocator* allocator, uintptr_t addr,
                         size_t size) {
    ASSERT(addr % PAGE_SIZE == 0);
    ASSERT(allocator->ranges);
    size = round_up(size, PAGE_SIZE);
    if (addr < allocator->start || allocator->end < addr + size)
        return -EINVAL;

    struct range* prev = NULL;
    struct range* it = allocator->ranges;
    while (it && it->base + it->size <= addr) {
        ASSERT((it->base + it->size <= addr) || (addr + size <= it->base));
        prev = it;
        it = it->next;
    }
    if (prev && prev->base + prev->size == addr) {
        prev->size += size;
        if (it && prev->base + prev->size == it->base) {
            // we're filling a gap
            prev->size += it->size;
            prev->next = it->next;
            kfree(it);
        }
        return 0;
    }
    if (it && it->base == addr + size) {
        it->base = addr;
        it->size += size;
        return 0;
    }

    if (prev)
        ASSERT(prev->base + prev->size < addr);
    if (it)
        ASSERT(addr + size < it->base);

    struct range* range = kmalloc(sizeof(struct range));
    if (!range)
        return -ENOMEM;
    range->base = addr;
    range->size = size;
    range->next = it;
    if (prev)
        prev->next = range;
    else
        allocator->ranges = range;

    return 0;
}

int range_allocator_clone(range_allocator* to, range_allocator* from) {
    ASSERT(from->ranges);

    to->start = from->start;
    to->end = from->end;

    struct range* prev = NULL;
    for (const struct range* it = from->ranges; it; it = it->next) {
        struct range* range = kmalloc(sizeof(struct range));
        if (!range)
            return -ENOMEM;
        range->base = it->base;
        range->size = it->size;
        range->next = NULL;
        if (prev)
            prev->next = range;
        else
            to->ranges = range;
        prev = range;
    }

    return 0;
}
