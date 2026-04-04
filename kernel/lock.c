#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/lock.h>
#include <kernel/panic.h>
#include <kernel/task/sched.h>
#include <kernel/task/task.h>

void mutex_lock(struct mutex* m) {
    struct task* task = current;
    for (;;) {
        ASSERT(arch_interrupts_enabled());
        struct task* expected = NULL;
        if (atomic_compare_exchange_strong(&m->holder, &expected, task)) {
            ASSERT(m->level == 0);
            break;
        }
        if (expected == task) {
            ASSERT(m->level > 0);
            break;
        }
        sched_yield();
    }
    ++m->level;
}

void mutex_unlock(struct mutex* m) {
    ASSERT(arch_interrupts_enabled());
    ASSERT(m->holder == current);
    ASSERT(m->level > 0);
    if (--m->level == 0)
        m->holder = NULL;
}

bool mutex_is_locked_by_current(const struct mutex* m) {
    if (m->holder != current)
        return false;
    ASSERT(m->level > 0);
    return true;
}

// Bits | Description
// 0-7  | CPU ID of the lock holder (0 if unlocked)
// 8    | 1 if interrupts were enabled when the lock was acquired, 0 otherwise
// 9-31 | Recursion level (0 means unlocked)

#define FLAGS_SHIFT CPU_ID_SHIFT
#define LEVEL_SHIFT (FLAGS_SHIFT + 1)

#define CPU_ID(x) ((x) & ((1U << CPU_ID_SHIFT) - 1))
#define PREV_INT_FLAG (1U << FLAGS_SHIFT)
#define LEVEL(x) ((x) >> LEVEL_SHIFT)
#define LEVEL_INCR (1U << LEVEL_SHIFT)

STATIC_ASSERT(UINT_WIDTH > LEVEL_SHIFT);

void spinlock_lock(struct spinlock* s) {
    unsigned desired = LEVEL_INCR;

    if (arch_interrupts_enabled())
        desired |= PREV_INT_FLAG;
    arch_disable_interrupts();

    unsigned long cpu_id = cpu_get_id();
    ASSERT(cpu_id < MAX_NUM_CPUS);
    desired |= cpu_id;

    for (;;) {
        unsigned expected = 0;
        if (atomic_compare_exchange_strong(&s->lock, &expected, desired))
            return;
        if (CPU_ID(expected) == cpu_id) {
            ASSERT(LEVEL(expected) > 0);
            s->lock += LEVEL_INCR;
            return;
        }
        cpu_relax();
    }
}

void spinlock_unlock(struct spinlock* s) {
    ASSERT(!arch_interrupts_enabled());
    unsigned v = s->lock;
    ASSERT(LEVEL(v) > 0);
    ASSERT(CPU_ID(v) == cpu_get_id());
    if (LEVEL(v) == 1) {
        s->lock = 0;
        if (v & PREV_INT_FLAG)
            arch_enable_interrupts();
    } else {
        s->lock -= LEVEL_INCR;
    }
}

bool spinlock_is_locked_by_current(const struct spinlock* s) {
    unsigned v = s->lock;
    return LEVEL(v) > 0 && CPU_ID(v) == cpu_get_id();
}
