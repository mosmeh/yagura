#pragma once

#include <stdalign.h>
#include <stdint.h>

typedef struct registers {
    uint32_t ss, gs, fs, es, ds;
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t num, err_code;
    uint32_t eip, cs, eflags, user_esp, user_ss;
} __attribute__((packed)) registers;

void dump_registers(const registers*);

struct fpu_state {
    alignas(16) unsigned char buffer[512];
};

void gdt_init(void);
void gdt_set_kernel_stack(uintptr_t stack_top);

void syscall_init(void);

extern uint32_t uptime;
void pit_init(void);

struct file* null_device_create(void);
struct file* zero_device_create(void);
struct file* full_device_create(void);
