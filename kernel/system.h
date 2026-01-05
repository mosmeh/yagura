#pragma once

#ifndef YAGURA_VERSION
#define YAGURA_VERSION "unknown"
#endif

#define AP_TRAMPOLINE_ADDR 0x8000
#define STACK_SIZE 0x4000

#define MSR_EFER 0xc0000080
#define MSR_STAR 0xc0000081
#define MSR_LSTAR 0xc0000082
#define MSR_SYSCALL_MASK 0xc0000084
#define MSR_FS_BASE 0xc0000100
#define MSR_GS_BASE 0xc0000101
#define MSR_KERNEL_GS_BASE 0xc0000102

#define EFER_LME 0x100
#define EFER_NX 0x800

#ifndef ASM_FILE

#include <common/macros.h>
#include <kernel/api/sys/types.h>
#include <kernel/api/sys/utsname.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdnoreturn.h>

typedef struct multiboot_info multiboot_info_t;

extern unsigned char init_end[];
extern unsigned char initial_kernel_stack_base[];
extern unsigned char initial_kernel_stack_top[];
extern unsigned char kernel_end[];

struct registers {
    uint64_t gs, fs;
    uint64_t r15, r14, r13, r12;
    uint64_t r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t interrupt_num, error_code;
    uint64_t rip, cs, rflags, rsp, ss;
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
ssize_t random_get_user(void* user_buffer, size_t count);

extern atomic_bool smp_active;

void smp_init(void);
void smp_start(void);

noreturn void reboot(void);
noreturn void halt(void);
noreturn void poweroff(void);

void handle_sysrq(char);

#endif
