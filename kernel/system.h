#pragma once

#ifndef YAGURA_VERSION
#define YAGURA_VERSION "unknown"
#endif

#define STACK_SIZE 0x4000

#ifndef __ASSEMBLER__

#include <common/macros.h>
#include <kernel/api/sys/types.h>
#include <kernel/api/sys/utsname.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdnoreturn.h>

extern unsigned char init_end[];
extern unsigned char initial_kernel_stack_base[];
extern unsigned char initial_kernel_stack_top[];
extern unsigned char kernel_end[];

noreturn void kernel_main(void);

void utsname_get(struct utsname*);
NODISCARD int utsname_set_hostname(const char*, size_t);
NODISCARD int utsname_set_domainname(const char*, size_t);

void cmdline_init(const char*);
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
ssize_t random_get_user(void* user_buffer, size_t count);

noreturn void reboot(const char* cmd);
noreturn void poweroff(void);
noreturn void halt(void);

void handle_sysrq(char);

void dump_stack_trace(uintptr_t ip, uintptr_t bp);

#endif
