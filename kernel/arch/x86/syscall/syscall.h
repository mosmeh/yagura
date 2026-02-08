#pragma once

#include <common/stddef.h>
#include <common/stdint.h>

struct user_desc;

void syscall_init(void);

long sys_arch_prctl(int op, unsigned long addr);

long sys_ia32_pread64(int fd, void* buf, size_t count, uint32_t pos_lo,
                      uint32_t pos_hi);
long sys_ia32_pwrite64(int fd, const void* buf, size_t count, uint32_t pos_lo,
                       uint32_t pos_hi);

long sys_ia32_truncate64(const char* path, unsigned long offset_low,
                         unsigned long offset_high);
long sys_ia32_ftruncate64(int fd, unsigned long offset_low,
                          unsigned long offset_high);

long sys_set_thread_area(struct user_desc* u_info);
long sys_get_thread_area(struct user_desc* u_info);
