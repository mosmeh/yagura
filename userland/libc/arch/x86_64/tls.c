#include "../../private.h"
#include <arch/tls.h>
#include <kernel/api/x86/asm/ldt.h>
#include <panic.h>
#include <pthread.h>

void __set_thread_area(void* addr) {
    struct user_desc tls_desc = {
        .entry_number = -1,
        .base_addr = (uintptr_t)addr,
        .limit = 0xfffff,
        .seg_32bit = 1,
        .limit_in_pages = 1,
    };
    ASSERT_OK(SYSCALL1(set_thread_area, &tls_desc));
    uint16_t fs = (tls_desc.entry_number * 8) | 3;
    __asm__ volatile("movw %0, %%fs" ::"r"(fs));
}

int __clone_impl(int (*fn)(void*), void* stack, int flags, void* arg,
                 pid_t* parent_tid, void* tls, pid_t* child_tid);

int __clone(int (*fn)(void*), void* stack, int flags, void* arg,
            pid_t* parent_tid, void* tls, pid_t* child_tid) {
    uint16_t fs;
    __asm__ volatile("movw %%fs, %0" : "=r"(fs));
    struct user_desc tls_desc = {
        .entry_number = fs / 8,
        .base_addr = (uintptr_t)tls,
        .limit = 0xfffff,
        .seg_32bit = 1,
        .limit_in_pages = 1,
    };
    return __clone_impl(fn, stack, flags, arg, parent_tid, &tls_desc,
                        child_tid);
}

pthread_t pthread_self(void) {
    pthread_t pth;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(pth));
    return pth;
}
