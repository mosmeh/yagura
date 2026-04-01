#pragma once

#include <common/stddef.h>

struct registers;

// The system call was interrupted by a signal and should be restarted if
// the sigaction has the SA_RESTART flag set.
#define ERESTARTSYS 512

// The system call handler has already set the return value by modifying
// the return value register directly, and should just return to user space
// without modification to the register.
#define ERAWRETURN 1024

typedef long (*syscall_fn)(struct registers*, const unsigned long args[6]);

struct syscall {
    const char* name;
    syscall_fn handler;
};

struct syscall_abi {
    const struct syscall* table;
    size_t table_len;

    void (*decode)(const struct registers*, unsigned long* out_number,
                   unsigned long out_args[6]);
    void (*set_return_value)(struct registers*, unsigned long value);
    void (*restart)(struct registers*);
};

void syscall_handle(const struct syscall_abi*, struct registers*);

#define SYSCALL0(name) __DEFINE_SYSCALL(name, (void), ())

#define SYSCALL1(name, type1, arg1)                                            \
    __DEFINE_SYSCALL(name, (type1 arg1), ((type1)__args[0]))

#define SYSCALL2(name, type1, arg1, type2, arg2)                               \
    __DEFINE_SYSCALL(name, (type1 arg1, type2 arg2),                           \
                     ((type1)__args[0], (type2)__args[1]))

#define SYSCALL3(name, type1, arg1, type2, arg2, type3, arg3)                  \
    __DEFINE_SYSCALL(name, (type1 arg1, type2 arg2, type3 arg3),               \
                     ((type1)__args[0], (type2)__args[1], (type3)__args[2]))

#define SYSCALL4(name, type1, arg1, type2, arg2, type3, arg3, type4, arg4)     \
    __DEFINE_SYSCALL(name, (type1 arg1, type2 arg2, type3 arg3, type4 arg4),   \
                     ((type1)__args[0], (type2)__args[1], (type3)__args[2],    \
                      (type4)__args[3]))

#define SYSCALL5(name, type1, arg1, type2, arg2, type3, arg3, type4, arg4,     \
                 type5, arg5)                                                  \
    __DEFINE_SYSCALL(                                                          \
        name, (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5),    \
        ((type1)__args[0], (type2)__args[1], (type3)__args[2],                 \
         (type4)__args[3], (type5)__args[4]))

#define SYSCALL6(name, type1, arg1, type2, arg2, type3, arg3, type4, arg4,     \
                 type5, arg5, type6, arg6)                                     \
    __DEFINE_SYSCALL(name,                                                     \
                     (type1 arg1, type2 arg2, type3 arg3, type4 arg4,          \
                      type5 arg5, type6 arg6),                                 \
                     ((type1)__args[0], (type2)__args[1], (type3)__args[2],    \
                      (type4)__args[3], (type5)__args[4], (type6)__args[5]))

// NOLINTBEGIN(bugprone-macro-parentheses)
#define SYSCALL_RAW(name, regs)                                                \
    __DEFINE_SYSCALL(name, (struct registers * regs), (__regs))
// NOLINTEND(bugprone-macro-parentheses)

#define __DEFINE_SYSCALL(name, def_args, call_args)                            \
    static long __sys_##name def_args;                                         \
                                                                               \
    long sys_##name(struct registers* __regs, const unsigned long __args[6]) { \
        (void)__regs;                                                          \
        (void)__args;                                                          \
        return __sys_##name call_args;                                         \
    }                                                                          \
                                                                               \
    static long __sys_##name def_args

#define DECLARE_SYSCALL(name)                                                  \
    long sys_##name(struct registers*, const unsigned long args[6]);

// Unimplemented syscall handler
DECLARE_SYSCALL(ni_syscall)

// Syscalls in scripts/syscall.tbl in Linux source code

DECLARE_SYSCALL(getcwd)
DECLARE_SYSCALL(dup)
DECLARE_SYSCALL(dup3)
DECLARE_SYSCALL(fcntl64)
DECLARE_SYSCALL(fcntl)
DECLARE_SYSCALL(ioctl)
DECLARE_SYSCALL(mknodat)
DECLARE_SYSCALL(mkdirat)
DECLARE_SYSCALL(unlinkat)
DECLARE_SYSCALL(symlinkat)
DECLARE_SYSCALL(linkat)
DECLARE_SYSCALL(renameat)
DECLARE_SYSCALL(mount)
DECLARE_SYSCALL(truncate)
DECLARE_SYSCALL(ftruncate)
DECLARE_SYSCALL(faccessat)
DECLARE_SYSCALL(chdir)
DECLARE_SYSCALL(fchdir)
DECLARE_SYSCALL(chroot)
DECLARE_SYSCALL(fchmod)
DECLARE_SYSCALL(fchmodat)
DECLARE_SYSCALL(fchownat)
DECLARE_SYSCALL(fchown)
DECLARE_SYSCALL(openat)
DECLARE_SYSCALL(close)
DECLARE_SYSCALL(pipe2)
DECLARE_SYSCALL(getdents64)
DECLARE_SYSCALL(llseek)
DECLARE_SYSCALL(lseek)
DECLARE_SYSCALL(read)
DECLARE_SYSCALL(write)
DECLARE_SYSCALL(readv)
DECLARE_SYSCALL(writev)
DECLARE_SYSCALL(pread64)
DECLARE_SYSCALL(pwrite64)
DECLARE_SYSCALL(preadv)
DECLARE_SYSCALL(pwritev)
DECLARE_SYSCALL(pselect6_time32)
DECLARE_SYSCALL(pselect6)
DECLARE_SYSCALL(ppoll_time32)
DECLARE_SYSCALL(ppoll)
DECLARE_SYSCALL(readlinkat)
DECLARE_SYSCALL(fstatat64)
DECLARE_SYSCALL(newfstatat)
DECLARE_SYSCALL(fstat64)
DECLARE_SYSCALL(newfstat)
DECLARE_SYSCALL(sync)
DECLARE_SYSCALL(fsync)
DECLARE_SYSCALL(fdatasync)
DECLARE_SYSCALL(exit)
DECLARE_SYSCALL(exit_group)
DECLARE_SYSCALL(unshare)
DECLARE_SYSCALL(nanosleep_time32)
DECLARE_SYSCALL(nanosleep)
DECLARE_SYSCALL(clock_settime32)
DECLARE_SYSCALL(clock_settime)
DECLARE_SYSCALL(clock_gettime32)
DECLARE_SYSCALL(clock_gettime)
DECLARE_SYSCALL(clock_getres_time32)
DECLARE_SYSCALL(clock_getres)
DECLARE_SYSCALL(clock_nanosleep_time32)
DECLARE_SYSCALL(clock_nanosleep)
DECLARE_SYSCALL(syslog)
DECLARE_SYSCALL(sched_getaffinity)
DECLARE_SYSCALL(sched_yield)
DECLARE_SYSCALL(kill)
DECLARE_SYSCALL(tkill)
DECLARE_SYSCALL(tgkill)
DECLARE_SYSCALL(rt_sigsuspend)
DECLARE_SYSCALL(rt_sigaction)
DECLARE_SYSCALL(rt_sigprocmask)
DECLARE_SYSCALL(rt_sigpending)
DECLARE_SYSCALL(rt_sigreturn)
DECLARE_SYSCALL(reboot)
DECLARE_SYSCALL(getresuid)
DECLARE_SYSCALL(getresgid)
DECLARE_SYSCALL(times)
DECLARE_SYSCALL(setpgid)
DECLARE_SYSCALL(getpgid)
DECLARE_SYSCALL(getsid)
DECLARE_SYSCALL(getgroups)
DECLARE_SYSCALL(newuname)
DECLARE_SYSCALL(sethostname)
DECLARE_SYSCALL(setdomainname)
DECLARE_SYSCALL(getrusage)
DECLARE_SYSCALL(umask)
DECLARE_SYSCALL(prctl)
DECLARE_SYSCALL(getcpu)
DECLARE_SYSCALL(gettimeofday)
DECLARE_SYSCALL(settimeofday)
DECLARE_SYSCALL(getpid)
DECLARE_SYSCALL(getppid)
DECLARE_SYSCALL(getuid)
DECLARE_SYSCALL(geteuid)
DECLARE_SYSCALL(getgid)
DECLARE_SYSCALL(getegid)
DECLARE_SYSCALL(gettid)
DECLARE_SYSCALL(sysinfo)
DECLARE_SYSCALL(socket)
DECLARE_SYSCALL(bind)
DECLARE_SYSCALL(listen)
DECLARE_SYSCALL(accept)
DECLARE_SYSCALL(connect)
DECLARE_SYSCALL(shutdown)
DECLARE_SYSCALL(munmap)
DECLARE_SYSCALL(execve)
DECLARE_SYSCALL(mmap)
DECLARE_SYSCALL(mprotect)
DECLARE_SYSCALL(msync)
DECLARE_SYSCALL(accept4)
DECLARE_SYSCALL(wait4)
DECLARE_SYSCALL(syncfs)
DECLARE_SYSCALL(process_vm_readv)
DECLARE_SYSCALL(process_vm_writev)
DECLARE_SYSCALL(renameat2)
DECLARE_SYSCALL(getrandom)
DECLARE_SYSCALL(preadv2)
DECLARE_SYSCALL(pwritev2)
DECLARE_SYSCALL(statx)
DECLARE_SYSCALL(faccessat2)

// Syscalls in arch/x86/entry/syscalls/syscall_64.tbl

DECLARE_SYSCALL(open)
DECLARE_SYSCALL(newstat)
DECLARE_SYSCALL(newlstat)
DECLARE_SYSCALL(poll)
DECLARE_SYSCALL(access)
DECLARE_SYSCALL(pipe)
DECLARE_SYSCALL(select)
DECLARE_SYSCALL(dup2)
DECLARE_SYSCALL(pause)
DECLARE_SYSCALL(fork)
DECLARE_SYSCALL(vfork)
DECLARE_SYSCALL(getdents)
DECLARE_SYSCALL(rename)
DECLARE_SYSCALL(mkdir)
DECLARE_SYSCALL(rmdir)
DECLARE_SYSCALL(creat)
DECLARE_SYSCALL(link)
DECLARE_SYSCALL(unlink)
DECLARE_SYSCALL(symlink)
DECLARE_SYSCALL(readlink)
DECLARE_SYSCALL(chmod)
DECLARE_SYSCALL(chown)
DECLARE_SYSCALL(lchown)
DECLARE_SYSCALL(getpgrp)
DECLARE_SYSCALL(mknod)
DECLARE_SYSCALL(time)

// Syscalls in arch/x86/entry/syscalls/syscall_32.tbl

DECLARE_SYSCALL(waitpid)
DECLARE_SYSCALL(time32)
DECLARE_SYSCALL(lchown16)
DECLARE_SYSCALL(stat)
DECLARE_SYSCALL(getuid16)
DECLARE_SYSCALL(stime32)
DECLARE_SYSCALL(fstat)
DECLARE_SYSCALL(getgid16)
DECLARE_SYSCALL(signal)
DECLARE_SYSCALL(geteuid16)
DECLARE_SYSCALL(getegid16)
DECLARE_SYSCALL(olduname)
DECLARE_SYSCALL(sigaction)
DECLARE_SYSCALL(sgetmask)
DECLARE_SYSCALL(ssetmask)
DECLARE_SYSCALL(sigsuspend)
DECLARE_SYSCALL(sigpending)
DECLARE_SYSCALL(getgroups16)
DECLARE_SYSCALL(old_select)
DECLARE_SYSCALL(lstat)
DECLARE_SYSCALL(old_readdir)
DECLARE_SYSCALL(old_mmap)
DECLARE_SYSCALL(fchown16)
DECLARE_SYSCALL(socketcall)
DECLARE_SYSCALL(uname)
DECLARE_SYSCALL(sigreturn)
DECLARE_SYSCALL(sigprocmask)
DECLARE_SYSCALL(getresuid16)
DECLARE_SYSCALL(getresgid16)
DECLARE_SYSCALL(chown16)
DECLARE_SYSCALL(mmap_pgoff)
DECLARE_SYSCALL(stat64)
DECLARE_SYSCALL(lstat64)

// Custom syscall

DECLARE_SYSCALL(dbgprint)
