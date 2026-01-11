#pragma once

#include <arch/cpu.h>
#include <stdnoreturn.h>

struct file;
struct cpu;
struct vec;
struct arch_cpu;

// Returns the ID of the current CPU.
uint8_t arch_cpu_get_id(void);

// Returns the hardware capabilities bitmask that should be exposed to userland
// as AT_HWCAP.
unsigned long arch_cpu_get_hwcap(void);

// Should be called in busy-wait loops.
void arch_cpu_relax(void);

// Halts the CPU indefinitely.
noreturn void arch_cpu_halt(void);

// Broadcast an Inter-Processor Interrupt to all other CPUs.
void arch_cpu_broadcast_ipi(void);

// Send an Inter-Processor Interrupt to the specified CPU.
void arch_cpu_unicast_ipi(struct cpu* dest);

int proc_print_cpuinfo(struct file*, struct vec*);
