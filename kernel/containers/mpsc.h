#pragma once

#include <common/stdatomic.h>
#include <common/string.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

// Multiple-producer single-consumer lock-free queue.
struct mpsc {
    size_t capacity;
    _Atomic(size_t) size, head, tail;
    _Atomic(uintptr_t) slots[];
};

static inline struct mpsc* mpsc_create(size_t capacity) {
    struct mpsc* mpsc =
        kmalloc(sizeof(struct mpsc) + capacity * sizeof(_Atomic(uintptr_t)));
    if (!mpsc)
        return ERR_PTR(-ENOMEM);
    *mpsc = (struct mpsc){.capacity = capacity};
    memset(mpsc->slots, 0, capacity * sizeof(_Atomic(uintptr_t)));
    return mpsc;
}

// Returns true if the element was enqueued, false if the queue was full.
NODISCARD static inline bool mpsc_enqueue(struct mpsc* mpsc, void* x) {
    size_t size =
        atomic_fetch_add_explicit(&mpsc->size, 1, memory_order_acquire);
    if (size >= mpsc->capacity) {
        atomic_fetch_sub_explicit(&mpsc->size, 1, memory_order_release);
        return false;
    }
    size_t head =
        atomic_fetch_add_explicit(&mpsc->head, 1, memory_order_acquire);
    _Atomic(uintptr_t)* slot = &mpsc->slots[head % mpsc->capacity];
    ASSERT(!*slot);
    ASSERT(!atomic_exchange_explicit(slot, (uintptr_t)x, memory_order_release));
    return true;
}

// Returns NULL if the queue was empty.
static inline void* mpsc_dequeue(struct mpsc* mpsc) {
    _Atomic(uintptr_t)* slot = &mpsc->slots[mpsc->tail];
    uintptr_t x = atomic_exchange_explicit(slot, 0, memory_order_acquire);
    if (!x)
        return NULL;
    if (++mpsc->tail >= mpsc->capacity)
        mpsc->tail = 0;
    ASSERT(atomic_fetch_sub_explicit(&mpsc->size, 1, memory_order_release));
    return (void*)x;
}
