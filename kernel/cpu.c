#include <kernel/arch/system.h>
#include <kernel/containers/mpsc.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

static struct cpu bsp;
size_t num_cpus = 1;
struct cpu* cpus[MAX_NUM_CPUS] = {&bsp};
static struct mpsc* msg_pool;

static void init_msg_queue(struct cpu* cpu) {
    cpu->queued_msgs = mpsc_create(MAX_NUM_CPUS);
    ASSERT(cpu->queued_msgs);

    struct ipi_message* msg = kmalloc(sizeof(struct ipi_message));
    ASSERT(msg);
    *msg = (struct ipi_message){0};
    ASSERT(mpsc_enqueue(msg_pool, msg));
}

struct cpu* cpu_add(void) {
    if (!msg_pool) {
        // First AP is being added
        msg_pool = mpsc_create(MAX_NUM_CPUS);
        ASSERT_PTR(msg_pool);
        init_msg_queue(&bsp);
    }

    ASSERT(num_cpus < ARRAY_SIZE(cpus));

    struct cpu* cpu = kmalloc(sizeof(struct cpu));
    ASSERT(cpu);
    *cpu = (struct cpu){0};
    init_msg_queue(cpu);

    cpus[num_cpus++] = cpu;
    return cpu;
}

struct cpu* cpu_get_bsp(void) { return &bsp; }

struct cpu* cpu_get_current(void) {
    ASSERT(!arch_interrupts_enabled());
    struct cpu* cpu = cpus[arch_cpu_get_id()];
    ASSERT(cpu);
    return cpu;
}

void cpu_relax(void) {
    cpu_process_messages();
    arch_cpu_relax();
}

struct ipi_message* cpu_alloc_message(void) {
    for (;;) {
        struct ipi_message* msg = mpsc_dequeue(msg_pool);
        if (msg) {
            ASSERT(refcount_get(&msg->refcount) == 0);
            return msg;
        }
        cpu_relax();
    }
}

void cpu_free_message(struct ipi_message* msg) {
    ASSERT(msg);
    ASSERT(refcount_get(&msg->refcount) == 0);
    while (!mpsc_enqueue(msg_pool, msg))
        cpu_relax();
}

void cpu_broadcast_message_queued(struct ipi_message* msg, bool eager) {
    {
        SCOPED_DISABLE_INTERRUPTS();
        uint8_t cpu_id = arch_cpu_get_id();
        for (size_t i = 0; i < num_cpus; ++i) {
            if (i == cpu_id)
                continue;
            while (!mpsc_enqueue(cpus[i]->queued_msgs, msg))
                cpu_relax();
        }
    }
    if (eager)
        arch_cpu_broadcast_ipi();
}

void cpu_broadcast_message_coalesced(unsigned int type, bool eager) {
    {
        SCOPED_DISABLE_INTERRUPTS();
        uint8_t cpu_id = arch_cpu_get_id();
        for (size_t i = 0; i < num_cpus; ++i) {
            if (i == cpu_id)
                continue;
            struct cpu* cpu = cpus[i];
            cpu->coalesced_msgs |= type;
        }
    }
    if (eager)
        arch_cpu_broadcast_ipi();
}

void cpu_unicast_message_queued(struct cpu* dest, struct ipi_message* msg,
                                bool eager) {
    while (!mpsc_enqueue(dest->queued_msgs, msg))
        cpu_relax();
    if (eager)
        arch_cpu_unicast_ipi(dest);
}

void cpu_unicast_message_coalesced(struct cpu* dest, unsigned int type,
                                   bool eager) {
    dest->coalesced_msgs |= type;
    if (eager)
        arch_cpu_unicast_ipi(dest);
}

static void handle_halt(struct ipi_message* msg) {
    (void)msg;
    arch_cpu_halt();
}

static void handle_flush_tlb(struct ipi_message* msg) {
    (void)msg;
    arch_flush_tlb_all();
}

static void handle_flush_tlb_range(struct ipi_message* msg) {
    ASSERT(msg);
    size_t virt_addr = msg->flush_tlb_range.virt_addr;
    size_t size = msg->flush_tlb_range.size;
    for (uintptr_t addr = virt_addr; addr < virt_addr + size; addr += PAGE_SIZE)
        arch_flush_tlb_single(addr);
}

static void (*const message_handlers[])(struct ipi_message*) = {
    [IPI_MESSAGE_HALT] = handle_halt,
    [IPI_MESSAGE_FLUSH_TLB] = handle_flush_tlb,
    [IPI_MESSAGE_FLUSH_TLB_RANGE] = handle_flush_tlb_range,
};

void cpu_process_messages(void) {
    if (!arch_smp_active())
        return;

    SCOPED_DISABLE_INTERRUPTS();
    struct cpu* cpu = cpu_get_current();
    for (;;) {
        int bit = __builtin_ffsl(cpu->coalesced_msgs);
        if (bit == 0)
            break;
        unsigned type = 1U << (bit - 1);
        cpu->coalesced_msgs &= ~(unsigned long)type;
        message_handlers[type](NULL);
    }
    for (;;) {
        struct ipi_message* msg = mpsc_dequeue(cpu->queued_msgs);
        if (!msg)
            break;
        message_handlers[msg->type](msg);
        refcount_dec(&msg->refcount);
    }
}
