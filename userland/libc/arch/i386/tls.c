#include "../../private.h"
#include <arch/tls.h>
#include <kernel/api/x86/asm/ldt.h>
#include <panic.h>
#include <pthread.h>

void __set_thread_area(void* addr) {
    struct user_desc tls_desc = {
        .entry_number = -1,
        .base_addr = (unsigned)addr,
        .limit = 0xfffff,
        .seg_32bit = 1,
        .limit_in_pages = 1,
    };
    ASSERT_OK(SYSCALL1(set_thread_area, &tls_desc));
    uint16_t gs = (tls_desc.entry_number * 8) | 3;
    __asm__ volatile("movw %0, %%gs" ::"r"(gs));
}

int __clone_impl(int (*fn)(void*), void* stack, int flags, void* arg,
                 pid_t* parent_tid, pid_t* child_tid, void* tls);

int __clone(int (*fn)(void*), void* stack, int flags, void* arg,
            pid_t* parent_tid, pid_t* child_tid, void* tls) {
    uint16_t gs;
    __asm__ volatile("movw %%gs, %0" : "=r"(gs));
    struct user_desc tls_desc = {
        .entry_number = gs / 8,
        .base_addr = (unsigned)tls,
        .limit = 0xfffff,
        .seg_32bit = 1,
        .limit_in_pages = 1,
    };
    return __clone_impl(fn, stack, flags, arg, parent_tid, child_tid,
                        &tls_desc);
}

pthread_t pthread_self(void) {
    pthread_t pth;
    __asm__ volatile("movl %%gs:0, %0" : "=r"(pth));
    return pth;
}
