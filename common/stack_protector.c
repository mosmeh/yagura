#include <common/panic.h>
#include <common/stack_protector.h>

// Initial value before STACK_CHK_GUARD_INIT is called.
#if UINTPTR_MAX == UINT64_MAX
uintptr_t __stack_chk_guard = 0x73ea082e725f96d5 & __CANARY_MASK;
#else
uintptr_t __stack_chk_guard = 0x1a395361 & __CANARY_MASK;
#endif

void __stack_chk_fail(void) { PANIC("Stack smashing detected"); }

void __stack_chk_fail_local(void) { __stack_chk_fail(); }
