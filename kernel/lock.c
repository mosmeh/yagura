#include "lock.h"
#include "interrupts.h"
#include "panic.h"
#include "process.h"

void mutex_init(mutex* m) {
    m->holder = NULL;
    m->level = 0;
    atomic_init(&m->lock, false);
}

void mutex_lock(mutex* m) {
    ASSERT(interrupts_enabled());

    for (;;) {
        bool expected = false;
        if (atomic_compare_exchange_strong_explicit(&m->lock, &expected, true,
                                                    memory_order_acq_rel,
                                                    memory_order_acquire)) {
            if (!m->holder || m->holder == current) {
                m->holder = current;
                ++m->level;
                atomic_store_explicit(&m->lock, false, memory_order_release);
                return;
            }
            atomic_store_explicit(&m->lock, false, memory_order_release);
        }
        process_switch();
    }
}

void mutex_unlock(mutex* m) {
    for (;;) {
        bool expected = false;
        if (atomic_compare_exchange_strong_explicit(&m->lock, &expected, true,
                                                    memory_order_acq_rel,
                                                    memory_order_acquire)) {
            ASSERT(m->holder == current);
            ASSERT(m->level > 0);
            if (--m->level == 0)
                m->holder = NULL;
            atomic_store_explicit(&m->lock, false, memory_order_release);
            return;
        }
        process_switch();
    }
}
