#pragma once

#include <common/stdbool.h>
#include <common/stddef.h>
#include <kernel/arch/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/memory/memory.h>

struct cpu {
    struct cpu* self;
    unsigned long id;

    _Atomic(struct task*) current_task;
    _Atomic(struct pagemap*) active_pagemap;

    struct task* idle_task;

    struct mpmc* queued_msgs;
    _Atomic(unsigned long) events;

    struct kmap_ctrl kmap;

    struct arch_cpu arch;
};

#define CPU_ID_SHIFT 8
#define MAX_NUM_CPUS (1UL << CPU_ID_SHIFT)

extern size_t num_cpus;
extern struct cpu* cpus[MAX_NUM_CPUS];

struct cpu* cpu_get_bsp(void);

static inline struct cpu* cpu_get_current(void) {
    ASSERT(!arch_interrupts_enabled());
    return ASSERT_PTR((void*)arch_cpu_read(offsetof(struct cpu, self)));
}

static inline unsigned long cpu_get_id(void) {
    SCOPED_DISABLE_INTERRUPTS();
    return arch_cpu_read(offsetof(struct cpu, id));
}

struct cpu* cpu_add(void);

void cpu_relax(void);

// Processes all pending messages and events for the current CPU.
void cpu_dispatch_requests(void);

#define CPU_EVENT_HALT 0

// Broadcasts an event to all other CPUs, immediately waking them up if they are
// idle. Events with the same type may be coalesced.
void cpu_broadcast_event(unsigned type);

#define CPU_MESSAGE_INVALIDATE_TLB_RANGE 0

struct cpu_message {
    unsigned type;
    _Atomic(unsigned long) pending[DIV_CEIL(MAX_NUM_CPUS, LONG_WIDTH)];
    struct {
        uintptr_t virt_addr;
        size_t npages;
    } invalidate_tlb_range;
};

struct cpu_message* cpu_message_alloc(void);
void cpu_message_free(struct cpu_message*);

// Queues a message to be processed by the destination CPU(s).
// The destination CPU is not explicitly notified until cpu_message_notify() is
// called.
void cpu_message_queue(struct cpu_message*, struct cpu*);

// Notifies the destination CPU(s) to process the message.
void cpu_message_notify(const struct cpu_message*);

// Waits for the message to be processed by all destination CPUs.
void cpu_message_wait(const struct cpu_message*);
