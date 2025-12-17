#pragma once

#define AP_TRAMPOLINE_ADDR 0x8000
#define STACK_SIZE 0x4000

#ifndef ASM_FILE

#include "api/sys/types.h"
#include "api/sys/utsname.h"
#include <common/extra.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdnoreturn.h>

typedef struct multiboot_info multiboot_info_t;

extern unsigned char init_end[];
extern unsigned char kernel_end[];

struct registers {
    uint32_t gs, fs, es, ds;
    uint32_t edi, esi, ebp, edx, ecx, ebx, eax;
    uint32_t interrupt_num, error_code;
    uint32_t eip, cs, eflags, esp, ss;
};

void dump_context(const struct registers*);

struct fpu_state {
    alignas(16) unsigned char buffer[512];
};

void utsname_get(struct utsname*);
NODISCARD int utsname_set_hostname(const char*, size_t);
NODISCARD int utsname_set_domainname(const char*, size_t);

void cmdline_init(const multiboot_info_t*);
const char* cmdline_get_raw(void);
const char* cmdline_lookup(const char* key);
bool cmdline_contains(const char* key);

struct symbol {
    uintptr_t addr;
    char type;
    const char* name;
};

void ksyms_init(void);
const struct symbol* ksyms_lookup(uintptr_t addr);
const struct symbol* ksyms_next(const struct symbol* symbol);

void random_init(void);
ssize_t random_get(void* buffer, size_t count);

extern atomic_bool smp_active;

void smp_init(void);
void smp_start(void);

noreturn void reboot(void);
noreturn void halt(void);
noreturn void poweroff(void);

void handle_sysrq(char);

#endif
