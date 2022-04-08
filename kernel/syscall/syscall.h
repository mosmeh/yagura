#pragma once

#include <kernel/api/syscall.h>

#define DECLARE_FUNC(name) uintptr_t sys_##name();
ENUMERATE_SYSCALLS(DECLARE_FUNC)
#undef DECLARE_FUNC
