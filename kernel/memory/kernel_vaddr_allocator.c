#include "memory.h"
#include <common/extra.h>
#include <kernel/api/sys/types.h>
#include <kernel/boot_defs.h>
#include <kernel/kprintf.h>
#include <kernel/lock.h>
#include <kernel/panic.h>
#include <stdbool.h>
#include <string.h>

#define NUM_PAGES ((KERNEL_HEAP_END - KERNEL_HEAP_START) / PAGE_SIZE)
#define BITMAP_LEN (NUM_PAGES / 32)

static uint32_t bitmap[BITMAP_LEN];
static mutex lock;

static bool bitmap_get(size_t i) {
    ASSERT((i >> 5) < BITMAP_LEN);
    return bitmap[i >> 5] & (1 << (i & 31));
}

static void bitmap_set(size_t i) {
    ASSERT((i >> 5) < BITMAP_LEN);
    bitmap[i >> 5] |= 1 << (i & 31);
}

static void bitmap_clear(size_t i) {
    ASSERT((i >> 5) < BITMAP_LEN);
    bitmap[i >> 5] &= ~(1 << (i & 31));
}

static ssize_t bitmap_find_first_fit(size_t num) {
    size_t streak = 0;
    for (size_t i = 0; i < BITMAP_LEN; ++i) {
        uint32_t cur = bitmap[i];
        size_t shift = 0;
        while (shift < 32) {
            if (cur == 0) {
                // there are leading zeros
                streak = 0;
                break;
            }

            int b = __builtin_ffs(cur);
            ASSERT(b > 0);
            cur >>= b - 1;
            shift += b - 1;
            if (b > 1) // there is at least one bit of gap
                streak = 0;

            int num_trailing_ones =
                cur == UINT32_MAX ? 32 : __builtin_ctz(~cur);
            if (streak + num_trailing_ones >= num)
                return i * 32 + shift - streak;

            streak += num_trailing_ones;
            cur >>= num_trailing_ones;
            shift += num_trailing_ones;
        }
    }
    return -ENOMEM;
}

void kernel_vaddr_allocator_init(void) {
    ASSERT(BITMAP_LEN * 32 == NUM_PAGES);
    memset32(bitmap, UINT32_MAX, BITMAP_LEN);
    mutex_init(&lock);
}

uintptr_t kernel_vaddr_allocator_alloc(size_t size) {
    size = round_up(size, PAGE_SIZE);
    size_t num_requested_pages = size / PAGE_SIZE;

    mutex_lock(&lock);

    ssize_t first_fit = bitmap_find_first_fit(num_requested_pages);
    if (IS_ERR(first_fit)) {
        mutex_unlock(&lock);
        kputs("Out of kernel virtual address space\n");
        return first_fit;
    }

    for (size_t i = 0; i < num_requested_pages; ++i) {
        ASSERT(bitmap_get(first_fit + i));
        bitmap_clear(first_fit + i);
    }

    mutex_unlock(&lock);
    return KERNEL_HEAP_START + first_fit * PAGE_SIZE;
}

void kernel_vaddr_allocator_free(uintptr_t addr, size_t size) {
    ASSERT(addr % PAGE_SIZE == 0);
    size = round_up(size, PAGE_SIZE);
    ASSERT(KERNEL_HEAP_START <= addr && addr + size <= KERNEL_HEAP_END);

    size_t base = (addr - KERNEL_HEAP_START) / PAGE_SIZE;
    mutex_lock(&lock);
    for (size_t i = 0; i < size / PAGE_SIZE; ++i) {
        ASSERT(!bitmap_get(base + i));
        bitmap_set(base + i);
    }
    mutex_unlock(&lock);
}
