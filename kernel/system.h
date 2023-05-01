#pragma once

#include "api/sys/types.h"
#include "forward.h"
#include <common/extra.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

typedef struct registers {
    uint32_t ss, gs, fs, es, ds;
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t num, err_code;
    uint32_t eip, cs, eflags, user_esp, user_ss;
} __attribute__((packed)) registers;

void dump_registers(const registers*);
void dump_stack_trace(const registers*);

struct fpu_state {
    alignas(16) unsigned char buffer[512];
};

void gdt_init(void);
void gdt_set_kernel_stack(uintptr_t stack_top);

void syscall_init(void);

extern uint32_t uptime;
void pit_init(void);

void cmdline_init(const multiboot_info_t*);
const char* cmdline_get_raw(void);
const char* cmdline_lookup(const char* key);
bool cmdline_contains(const char* key);

void random_init(void);
ssize_t random_get(void* buffer, size_t count);

noreturn void reboot(void);
noreturn void halt(void);
noreturn void poweroff(void);

struct inode* null_device_create(void);
struct inode* zero_device_create(void);
struct inode* full_device_create(void);
struct inode* random_device_create(void);
struct inode* urandom_device_create(void);

NODISCARD bool ac97_init(void);
struct inode* ac97_device_create(void);
