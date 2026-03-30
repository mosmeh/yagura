#pragma once

#include <common/macros.h>
#include <common/stdbool.h>
#include <common/stddef.h>
#include <kernel/api/sys/types.h>
#include <kernel/api/sys/utsname.h>

struct file;
struct vec;

#ifndef YAGURA_VERSION
#define YAGURA_VERSION "unknown"
#endif

extern unsigned char init_end[];
extern unsigned char initial_kernel_stack_base[];
extern unsigned char initial_kernel_stack_top[];
extern unsigned char kernel_end[];

_Noreturn void kernel_main(void);

void utsname_get(struct utsname*);
NODISCARD int utsname_set_hostname(const char*, size_t);
NODISCARD int utsname_set_domainname(const char*, size_t);

int proc_print_version(struct file*, struct vec*);

void cmdline_init(const char*);
const char* cmdline_lookup(const char* key);
bool cmdline_contains(const char* key);
int proc_print_cmdline(struct file*, struct vec*);

struct symbol {
    uintptr_t addr;
    char type;
    const char* name;
};

void ksyms_init(void);
const struct symbol* ksyms_lookup(uintptr_t addr);
int proc_print_kallsyms(struct file*, struct vec*);

void random_init(void);
NODISCARD ssize_t random_get(void* buffer, size_t count);
NODISCARD ssize_t random_get_user(void* user_buffer, size_t count);

_Noreturn void reboot(const char* cmd);
_Noreturn void poweroff(void);
_Noreturn void halt(void);

void handle_sysrq(char);

void dump_stack_trace(uintptr_t ip, uintptr_t bp);
