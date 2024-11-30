#include "lock.h"
#include "cpu.h"
#include "interrupts/interrupts.h"
#include "panic.h"
#include "sched.h"
#include "task.h"

void mutex_lock(struct mutex* m) {
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
        sched_yield(true);
    }
}

void mutex_unlock(struct mutex* m) {
    ASSERT(interrupts_enabled());

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
        sched_yield(true);
    }
}

bool mutex_is_locked_by_current(const struct mutex* m) {
    if (m->holder != current)
        return false;
    ASSERT(m->level > 0);
    return true;
}

#define SPINLOCK_LOCKED 0x1
#define SPINLOCK_PUSHED_INTERRUPT 0x2
#define SPINLOCK_CPU_ID_SHIFT 2

void spinlock_lock(struct spinlock* s) {
    unsigned desired = SPINLOCK_LOCKED;
    if (interrupts_enabled())
        desired |= SPINLOCK_PUSHED_INTERRUPT;
    cli();
    uint8_t cpu_id = cpu_get_id();
    desired |= (unsigned)cpu_id << SPINLOCK_CPU_ID_SHIFT;
    for (;;) {
        unsigned expected = 0;
        if (atomic_compare_exchange_strong(&s->lock, &expected, desired)) {
            ASSERT(s->level == 0);
            break;
        }
        if ((expected >> SPINLOCK_CPU_ID_SHIFT) == cpu_id) {
            ASSERT(expected & SPINLOCK_LOCKED);
            break;
        }
        cpu_pause();
    }
    ++s->level;
}

void spinlock_unlock(struct spinlock* s) {
    ASSERT(!interrupts_enabled());
    unsigned v = s->lock;
    ASSERT(v & SPINLOCK_LOCKED);
    ASSERT((v >> SPINLOCK_CPU_ID_SHIFT) == cpu_get_id());
    ASSERT(s->level > 0);
    if (--s->level == 0) {
        atomic_store_explicit(&s->lock, 0, memory_order_release);
        if (v & SPINLOCK_PUSHED_INTERRUPT)
            sti();
    }
}
