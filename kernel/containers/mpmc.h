#pragma once

#include <common/stdatomic.h>
#include <common/string.h>
#include <kernel/memory/memory.h>

// Multi-producer multi-consumer concurrent queue based on
// https://github.com/rigtorp/MPMCQueue
struct mpmc {
    size_t capacity;
    _Atomic(size_t) head, tail;
    struct mpmc_slot {
        _Atomic(size_t) turn;
        void* value;
    } slots[];
};

static inline struct mpmc* mpmc_create(size_t capacity) {
    if (capacity == 0)
        return ERR_PTR(-EINVAL);
    struct mpmc* mpmc =
        kmalloc(sizeof(struct mpmc) + capacity * sizeof(struct mpmc_slot));
    if (!mpmc)
        return ERR_PTR(-ENOMEM);
    *mpmc = (struct mpmc){.capacity = capacity};
    memset(mpmc->slots, 0, capacity * sizeof(struct mpmc_slot));
    return mpmc;
}

// Returns true if the value was enqueued, false if the queue is full.
NODISCARD static inline bool mpmc_push(struct mpmc* mpmc, void* value) {
    ASSERT(value); // NULL is used to indicate an empty queue.
    size_t head = atomic_load_explicit(&mpmc->head, memory_order_acquire);
    for (;;) {
        struct mpmc_slot* slot = &mpmc->slots[head % mpmc->capacity];
        size_t head_turn = head / mpmc->capacity;
        size_t turn = atomic_load_explicit(&slot->turn, memory_order_acquire);
        if (head_turn * 2 != turn) {
            size_t prev_head = head;
            head = atomic_load_explicit(&mpmc->head, memory_order_acquire);
            if (head == prev_head)
                return false;
            continue;
        }
        if (atomic_compare_exchange_strong(&mpmc->head, &head, head + 1)) {
            slot->value = value;
            atomic_store_explicit(&slot->turn, head_turn * 2 + 1,
                                  memory_order_release);
            return true;
        }
    }
}

// Returns the value if the queue is not empty, NULL if the queue is empty.
static inline void* mpmc_pop(struct mpmc* mpmc) {
    size_t tail = atomic_load_explicit(&mpmc->tail, memory_order_acquire);
    for (;;) {
        struct mpmc_slot* slot = &mpmc->slots[tail % mpmc->capacity];
        size_t tail_turn = tail / mpmc->capacity;
        size_t turn = atomic_load_explicit(&slot->turn, memory_order_acquire);
        if (tail_turn * 2 + 1 != turn) {
            size_t prev_tail = tail;
            tail = atomic_load_explicit(&mpmc->tail, memory_order_acquire);
            if (tail == prev_tail)
                return NULL;
            continue;
        }
        if (atomic_compare_exchange_strong(&mpmc->tail, &tail, tail + 1)) {
            void* value = slot->value;
            atomic_store_explicit(&slot->turn, tail_turn * 2 + 2,
                                  memory_order_release);
            return value;
        }
    }
}
