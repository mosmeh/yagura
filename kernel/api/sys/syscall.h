#pragma once

#define SYSCALL_VECTOR 0x80

// The syscall numbers are defined in the Linux kernel source code:
// arch/x86/entry/syscalls/syscall_32.tbl
#define SYS_exit 1
#define SYS_fork 2
#define SYS_read 3
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_waitpid 7
#define SYS_link 9
#define SYS_unlink 10
#define SYS_execve 11
#define SYS_chdir 12
#define SYS_mknod 14
#define SYS_lseek 19
#define SYS_getpid 20
#define SYS_mount 21
#define SYS_kill 37
#define SYS_rename 38
#define SYS_mkdir 39
#define SYS_rmdir 40
#define SYS_pipe 42
#define SYS_times 43
#define SYS_ioctl 54
#define SYS_fcntl 55
#define SYS_setpgid 57
#define SYS_dup2 63
#define SYS_sigaction 67
#define SYS_sigsuspend 72
#define SYS_sigpending 73
#define SYS_symlink 83
#define SYS_readlink 85
#define SYS_reboot 88
#define SYS_munmap 91
#define SYS_ftruncate 93
#define SYS_stat 106
#define SYS_lstat 107
#define SYS_uname 109
#define SYS_sigreturn 119
#define SYS_clone 120
#define SYS_sigprocmask 126
#define SYS_getpgid 132
#define SYS_getdents 141
#define SYS_sched_yield 158
#define SYS_poll 168
#define SYS_getcwd 183
#define SYS_mmap 192
#define SYS_gettid 224
#define SYS_exit_group 252
#define SYS_clock_gettime 265
#define SYS_clock_nanosleep 267
#define SYS_socket 359
#define SYS_bind 361
#define SYS_connect 362
#define SYS_listen 363
#define SYS_accept4 364
#define SYS_shutdown 373

// Custom syscall
#define SYS_dbgprint 1024
