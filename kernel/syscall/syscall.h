#pragma once

#include <kernel/api/sys/syscall.h>

#define DECLARE_FUNC(name) uintptr_t sys_##name();
ENUMERATE_SYSCALLS(DECLARE_FUNC)
#undef DECLARE_FUNC
