#pragma once

#include <common/stdbool.h>
#include <common/stddef.h>
#include <kernel/arch/cpu.h>
#include <kernel/memory/memory.h>

struct cpu {
    _Atomic(struct task*) current_task;
    struct task* idle_task;

    struct mpsc* queued_msgs;
    _Atomic(unsigned long) coalesced_msgs;

    struct kmap_ctrl kmap;

    struct arch_cpu arch;
};

#define MAX_NUM_CPUS (UINT8_MAX + 1)

extern size_t num_cpus;
extern struct cpu* cpus[MAX_NUM_CPUS];

struct cpu* cpu_get_bsp(void);
struct cpu* cpu_get_current(void);

struct cpu* cpu_add(void);

void cpu_relax(void);

#define IPI_MESSAGE_HALT 0x1
#define IPI_MESSAGE_FLUSH_TLB 0x2
#define IPI_MESSAGE_FLUSH_TLB_RANGE 0x4

struct ipi_message {
    unsigned type;
    refcount_t refcount;
    struct {
        uintptr_t virt_addr;
        size_t size;
    } flush_tlb_range;
};

struct ipi_message* cpu_alloc_message(void);
void cpu_free_message(struct ipi_message*);

void cpu_broadcast_message_queued(struct ipi_message*, bool eager);
void cpu_broadcast_message_coalesced(unsigned type, bool eager);

void cpu_unicast_message_queued(struct cpu*, struct ipi_message*, bool eager);
void cpu_unicast_message_coalesced(struct cpu*, unsigned type, bool eager);

void cpu_process_messages(void);
