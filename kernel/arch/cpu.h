#pragma once

#include <arch/cpu.h>

struct file;
struct cpu;
struct vec;
struct arch_cpu;

// Reads a value from the struct cpu for this CPU at the specified offset.
unsigned long arch_cpu_read(size_t offset);

// Returns the hardware capabilities bitmask that should be exposed to userland
// as AT_HWCAP.
unsigned long arch_cpu_get_hwcap(void);

// Should be called in busy-wait loops.
void arch_cpu_relax(void);

// Halts the CPU indefinitely.
_Noreturn void arch_cpu_halt(void);

// Broadcast an Inter-Processor Interrupt to all other CPUs.
void arch_cpu_broadcast_ipi(void);

// Send an Inter-Processor Interrupt to the specified CPU.
void arch_cpu_unicast_ipi(struct cpu* dest);

int proc_print_cpuinfo(struct file*, struct vec*);
