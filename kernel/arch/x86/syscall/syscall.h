#pragma once

#include <kernel/syscall/syscall.h>

void syscall_init(void);
void syscall_init_cpu(void);

DECLARE_SYSCALL(arch_prctl)

DECLARE_SYSCALL(ia32_pread64)
DECLARE_SYSCALL(ia32_pwrite64)
DECLARE_SYSCALL(ia32_truncate64)
DECLARE_SYSCALL(ia32_ftruncate64)

DECLARE_SYSCALL(set_thread_area)
DECLARE_SYSCALL(get_thread_area)
