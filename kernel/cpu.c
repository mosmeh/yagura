#include <kernel/arch/system.h>
#include <kernel/containers/mpmc.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

static struct cpu bsp = {
    .self = &bsp,
    .id = 0,
};
size_t num_cpus = 1;
struct cpu* cpus[MAX_NUM_CPUS] = {&bsp};

#define NUM_MSGS_PER_CPU 4
static struct mpmc* msg_pool;

static void init_msg_queue(struct cpu* cpu) {
    cpu->queued_msgs = ASSERT_PTR(mpmc_create(MAX_NUM_CPUS * NUM_MSGS_PER_CPU));

    for (size_t i = 0; i < NUM_MSGS_PER_CPU; ++i) {
        struct cpu_message* msg =
            ASSERT_PTR(kmalloc(sizeof(struct cpu_message)));
        *msg = (struct cpu_message){0};
        ASSERT(mpmc_push(msg_pool, msg));
    }
}

struct cpu* cpu_add(void) {
    if (!msg_pool) {
        // First AP is being added
        msg_pool = ASSERT_PTR(mpmc_create(MAX_NUM_CPUS * NUM_MSGS_PER_CPU));
        init_msg_queue(&bsp);
    }

    ASSERT(num_cpus < ARRAY_SIZE(cpus));

    struct cpu* cpu = ASSERT_PTR(kmalloc(sizeof(struct cpu)));
    *cpu = (struct cpu){
        .self = cpu,
        .id = num_cpus,
    };
    init_msg_queue(cpu);

    cpus[num_cpus++] = cpu;
    return cpu;
}

struct cpu* cpu_get_bsp(void) { return &bsp; }

void cpu_relax(void) {
    cpu_dispatch_requests();
    arch_cpu_relax();
}

#define BITMAP_INDEX(i) ((i) / LONG_WIDTH)
#define BITMAP_MASK(i) (1UL << ((i) % LONG_WIDTH))

// Returns true if the pending bit was newly set, false if it was already set.
static bool cpu_message_set_pending(struct cpu_message* msg, size_t cpu_id) {
    ASSERT(cpu_id < num_cpus);
    unsigned long mask = BITMAP_MASK(cpu_id);
    unsigned long prev =
        atomic_fetch_or(&msg->pending[BITMAP_INDEX(cpu_id)], mask);
    return !(prev & mask);
}

// Returns true if the pending bit was cleared, false if it was already clear.
static bool cpu_message_clear_pending(struct cpu_message* msg, size_t cpu_id) {
    ASSERT(cpu_id < num_cpus);
    unsigned long mask = BITMAP_MASK(cpu_id);
    unsigned long prev =
        atomic_fetch_and(&msg->pending[BITMAP_INDEX(cpu_id)], ~mask);
    return prev & mask;
}

static bool cpu_message_is_pending(const struct cpu_message* msg,
                                   size_t cpu_id) {
    ASSERT(cpu_id < num_cpus);
    return msg->pending[BITMAP_INDEX(cpu_id)] & BITMAP_MASK(cpu_id);
}

static size_t cpu_message_num_pending(const struct cpu_message* msg) {
    size_t n = 0;
    for (size_t i = 0; i < num_cpus; ++i) {
        if (cpu_message_is_pending(msg, i))
            ++n;
    }
    return n;
}

static bool cpu_message_has_pending(const struct cpu_message* msg) {
    for (size_t i = 0; i < ARRAY_SIZE(msg->pending); ++i) {
        if (msg->pending[i])
            return true;
    }
    return false;
}

static void on_event_halt(void) { arch_cpu_halt(); }

static void on_message_invalidate_tlb_range(struct cpu_message* msg) {
    ASSERT_PTR(msg);
    size_t virt_addr = msg->invalidate_tlb_range.virt_addr;
    size_t npages = msg->invalidate_tlb_range.npages;
    for (size_t i = 0; i < npages; ++i)
        arch_invalidate_tlb_page(virt_addr + (i << PAGE_SHIFT));
}

void cpu_dispatch_requests(void) {
    if (!arch_smp_active())
        return;

    SCOPED_DISABLE_INTERRUPTS();
    struct cpu* cpu = cpu_get_current();
    for (;;) {
        int bit = __builtin_ffsl(cpu->events);
        if (bit == 0)
            break;
        unsigned type = bit - 1;
        cpu->events &= ~(1UL << type);
        switch (type) {
        case CPU_EVENT_HALT:
            on_event_halt();
            break;
        default:
            UNREACHABLE();
        }
    }
    for (;;) {
        struct cpu_message* msg = mpmc_pop(cpu->queued_msgs);
        if (!msg)
            break;
        switch (msg->type) {
        case CPU_MESSAGE_INVALIDATE_TLB_RANGE:
            on_message_invalidate_tlb_range(msg);
            break;
        default:
            UNREACHABLE();
        }
        ASSERT(cpu_message_clear_pending(msg, cpu->id));
    }
}

void cpu_broadcast_event(unsigned type) {
    if (!arch_smp_active())
        return;

    SCOPED_DISABLE_INTERRUPTS();
    unsigned long cpu_id = cpu_get_id();
    for (size_t i = 0; i < num_cpus; ++i) {
        if (i != cpu_id)
            cpus[i]->events |= 1UL << type;
    }
    arch_cpu_broadcast_ipi();
}

struct cpu_message* cpu_message_alloc(void) {
    for (;;) {
        struct cpu_message* msg = NULL;
        {
            SCOPED_DISABLE_INTERRUPTS();
            msg = mpmc_pop(msg_pool);
        }
        if (msg) {
            ASSERT(!cpu_message_has_pending(msg));
            return msg;
        }
        cpu_relax();
    }
}

void cpu_message_free(struct cpu_message* msg) {
    ASSERT_PTR(msg);
    ASSERT(!cpu_message_has_pending(msg));
    for (;;) {
        {
            SCOPED_DISABLE_INTERRUPTS();
            if (mpmc_push(msg_pool, msg))
                return;
        }
        cpu_relax();
    }
}

void cpu_message_queue(struct cpu_message* msg, struct cpu* dest) {
    ASSERT(arch_smp_active());
    ASSERT_PTR(msg);
    ASSERT_PTR(dest);
    ASSERT(cpu_message_set_pending(msg, dest->id));
    for (;;) {
        {
            SCOPED_DISABLE_INTERRUPTS();
            if (mpmc_push(dest->queued_msgs, msg))
                return;
        }
        cpu_relax();
    }
}

void cpu_message_notify(const struct cpu_message* msg) {
    ASSERT(arch_smp_active());
    ASSERT_PTR(msg);
    ASSERT(!arch_interrupts_enabled());
    if (cpu_message_num_pending(msg) * 2 >= num_cpus) {
        // If we need to send to the majority of CPUs, use broadcast.
        arch_cpu_broadcast_ipi();
        return;
    }
    for (size_t i = 0; i < num_cpus; ++i) {
        if (cpu_message_is_pending(msg, i))
            arch_cpu_unicast_ipi(cpus[i]);
    }
}

void cpu_message_wait(const struct cpu_message* msg) {
    ASSERT(arch_smp_active());
    ASSERT_PTR(msg);
    while (cpu_message_has_pending(msg))
        cpu_relax();
}
