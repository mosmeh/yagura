#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#define KPANIC(msg) kpanic("PANIC: " msg, __FILE__, __LINE__)
#define KUNREACHABLE() KPANIC("Unreachable")
#define KUNIMPLEMENTED() KPANIC("Unimplemented")
#define KASSERT(cond) ((cond) ? (void)0 : KPANIC("Assertion failed: " #cond))

noreturn void kpanic(const char* message, const char* file, size_t line);

typedef struct registers {
    uint32_t ss, gs, fs, es, ds;
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t num, err_code;
    uint32_t eip, cs, eflags, user_esp, user_ss;
} registers;

void dump_registers(const registers*);

#define IRQ0 0x20

void gdt_init(void);
void idt_init(void);
void irq_init(void);
void pit_init(uint32_t freq);
void syscall_init(void);

void gdt_set_kernel_stack(uintptr_t stack_top);

typedef void (*interrupt_handler_fn)(registers*);

void idt_set_gate(uint8_t idx, uint32_t base, uint16_t segment_selector,
                  uint8_t flags);
void idt_register_interrupt_handler(uint8_t num, interrupt_handler_fn handler);
void idt_set_user_callable(uint8_t idx);
void idt_flush(void);
