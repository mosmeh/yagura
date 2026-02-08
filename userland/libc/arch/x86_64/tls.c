#include "../../private.h"
#include <arch/tls.h>
#include <asm/prctl.h>
#include <panic.h>
#include <pthread.h>

void __set_thread_area(void* addr) {
    ASSERT_OK(SYSCALL2(arch_prctl, ARCH_SET_FS, addr));
}

pthread_t pthread_self(void) {
    pthread_t pth;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(pth));
    return pth;
}
