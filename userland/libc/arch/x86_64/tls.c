#include "../../private.h"
#include <arch/tls.h>
#include <asm/prctl.h>
#include <panic.h>

void __set_thread_area(void* addr) {
    ASSERT_OK(SYSCALL2(arch_prctl, ARCH_SET_FS, addr));
}
