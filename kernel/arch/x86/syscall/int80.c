#include <kernel/api/i386/asm/unistd.h>
#include <kernel/arch/x86/interrupts/interrupts.h>
#include <kernel/arch/x86/syscall/syscall.h>
#include <kernel/arch/x86/task/context.h>
#include <kernel/interrupts.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

// Linux syscalls introduced up to Linux 5.1.
// Keep this list in sync with arch/x86/entry/syscalls/syscall_32.tbl
// in the Linux kernel source.
// The unimplemented syscalls are mapped to sys_ni_syscall.
#define ENUMERATE_SYSCALLS(F)                                                  \
    F(restart_syscall, sys_ni_syscall)                                         \
    F(exit, sys_exit)                                                          \
    F(fork, sys_fork)                                                          \
    F(read, sys_read)                                                          \
    F(write, sys_write)                                                        \
    F(open, sys_open)                                                          \
    F(close, sys_close)                                                        \
    F(waitpid, sys_waitpid)                                                    \
    F(creat, sys_creat)                                                        \
    F(link, sys_link)                                                          \
    F(unlink, sys_unlink)                                                      \
    F(execve, sys_execve)                                                      \
    F(chdir, sys_chdir)                                                        \
    F(time, sys_time32)                                                        \
    F(mknod, sys_mknod)                                                        \
    F(chmod, sys_chmod)                                                        \
    F(lchown, sys_lchown16)                                                    \
    F(break, sys_ni_syscall)                                                   \
    F(oldstat, sys_stat)                                                       \
    F(lseek, sys_lseek)                                                        \
    F(getpid, sys_getpid)                                                      \
    F(mount, sys_mount)                                                        \
    F(umount, sys_ni_syscall)                                                  \
    F(setuid, sys_ni_syscall)                                                  \
    F(getuid, sys_getuid16)                                                    \
    F(stime, sys_stime32)                                                      \
    F(ptrace, sys_ni_syscall)                                                  \
    F(alarm, sys_ni_syscall)                                                   \
    F(oldfstat, sys_fstat)                                                     \
    F(pause, sys_pause)                                                        \
    F(utime, sys_ni_syscall)                                                   \
    F(stty, sys_ni_syscall)                                                    \
    F(gtty, sys_ni_syscall)                                                    \
    F(access, sys_access)                                                      \
    F(nice, sys_ni_syscall)                                                    \
    F(ftime, sys_ni_syscall)                                                   \
    F(sync, sys_sync)                                                          \
    F(kill, sys_kill)                                                          \
    F(rename, sys_rename)                                                      \
    F(mkdir, sys_mkdir)                                                        \
    F(rmdir, sys_rmdir)                                                        \
    F(dup, sys_dup)                                                            \
    F(pipe, sys_pipe)                                                          \
    F(times, sys_times)                                                        \
    F(prof, sys_ni_syscall)                                                    \
    F(brk, sys_ni_syscall)                                                     \
    F(setgid, sys_ni_syscall)                                                  \
    F(getgid, sys_getgid16)                                                    \
    F(signal, sys_signal)                                                      \
    F(geteuid, sys_geteuid16)                                                  \
    F(getegid, sys_getegid16)                                                  \
    F(acct, sys_ni_syscall)                                                    \
    F(umount2, sys_ni_syscall)                                                 \
    F(lock, sys_ni_syscall)                                                    \
    F(ioctl, sys_ioctl)                                                        \
    F(fcntl, sys_fcntl)                                                        \
    F(mpx, sys_ni_syscall)                                                     \
    F(setpgid, sys_setpgid)                                                    \
    F(ulimit, sys_ni_syscall)                                                  \
    F(oldolduname, sys_olduname)                                               \
    F(umask, sys_umask)                                                        \
    F(chroot, sys_chroot)                                                      \
    F(ustat, sys_ni_syscall)                                                   \
    F(dup2, sys_dup2)                                                          \
    F(getppid, sys_getppid)                                                    \
    F(getpgrp, sys_getpgrp)                                                    \
    F(setsid, sys_ni_syscall)                                                  \
    F(sigaction, sys_sigaction)                                                \
    F(sgetmask, sys_sgetmask)                                                  \
    F(ssetmask, sys_ssetmask)                                                  \
    F(setreuid, sys_ni_syscall)                                                \
    F(setregid, sys_ni_syscall)                                                \
    F(sigsuspend, sys_sigsuspend)                                              \
    F(sigpending, sys_sigpending)                                              \
    F(sethostname, sys_sethostname)                                            \
    F(setrlimit, sys_ni_syscall)                                               \
    F(getrlimit, sys_ni_syscall)                                               \
    F(getrusage, sys_ni_syscall)                                               \
    F(gettimeofday, sys_gettimeofday)                                          \
    F(settimeofday, sys_settimeofday)                                          \
    F(getgroups, sys_getgroups16)                                              \
    F(setgroups, sys_ni_syscall)                                               \
    F(select, sys_old_select)                                                  \
    F(symlink, sys_symlink)                                                    \
    F(oldlstat, sys_lstat)                                                     \
    F(readlink, sys_readlink)                                                  \
    F(uselib, sys_ni_syscall)                                                  \
    F(swapon, sys_ni_syscall)                                                  \
    F(reboot, sys_reboot)                                                      \
    F(readdir, sys_old_readdir)                                                \
    F(mmap, sys_old_mmap)                                                      \
    F(munmap, sys_munmap)                                                      \
    F(truncate, sys_truncate)                                                  \
    F(ftruncate, sys_ftruncate)                                                \
    F(fchmod, sys_fchmod)                                                      \
    F(fchown, sys_fchown16)                                                    \
    F(getpriority, sys_ni_syscall)                                             \
    F(setpriority, sys_ni_syscall)                                             \
    F(profil, sys_ni_syscall)                                                  \
    F(statfs, sys_ni_syscall)                                                  \
    F(fstatfs, sys_ni_syscall)                                                 \
    F(ioperm, sys_ni_syscall)                                                  \
    F(socketcall, sys_socketcall)                                              \
    F(syslog, sys_ni_syscall)                                                  \
    F(setitimer, sys_ni_syscall)                                               \
    F(getitimer, sys_ni_syscall)                                               \
    F(stat, sys_newstat)                                                       \
    F(lstat, sys_newlstat)                                                     \
    F(fstat, sys_newfstat)                                                     \
    F(olduname, sys_uname)                                                     \
    F(iopl, sys_ni_syscall)                                                    \
    F(vhangup, sys_ni_syscall)                                                 \
    F(idle, sys_ni_syscall)                                                    \
    F(vm86old, sys_ni_syscall)                                                 \
    F(wait4, sys_wait4)                                                        \
    F(swapoff, sys_ni_syscall)                                                 \
    F(sysinfo, sys_sysinfo)                                                    \
    F(ipc, sys_ni_syscall)                                                     \
    F(fsync, sys_fsync)                                                        \
    F(sigreturn, sys_sigreturn)                                                \
    F(clone, sys_int80_clone)                                                  \
    F(setdomainname, sys_setdomainname)                                        \
    F(uname, sys_newuname)                                                     \
    F(modify_ldt, sys_ni_syscall)                                              \
    F(adjtimex, sys_ni_syscall)                                                \
    F(mprotect, sys_mprotect)                                                  \
    F(sigprocmask, sys_sigprocmask)                                            \
    F(create_module, sys_ni_syscall)                                           \
    F(init_module, sys_ni_syscall)                                             \
    F(delete_module, sys_ni_syscall)                                           \
    F(get_kernel_syms, sys_ni_syscall)                                         \
    F(quotactl, sys_ni_syscall)                                                \
    F(getpgid, sys_getpgid)                                                    \
    F(fchdir, sys_fchdir)                                                      \
    F(bdflush, sys_ni_syscall)                                                 \
    F(sysfs, sys_ni_syscall)                                                   \
    F(personality, sys_ni_syscall)                                             \
    F(afs_syscall, sys_ni_syscall)                                             \
    F(setfsuid, sys_ni_syscall)                                                \
    F(setfsgid, sys_ni_syscall)                                                \
    F(_llseek, sys_llseek)                                                     \
    F(getdents, sys_getdents)                                                  \
    F(_newselect, sys_select)                                                  \
    F(flock, sys_ni_syscall)                                                   \
    F(msync, sys_msync)                                                        \
    F(readv, sys_readv)                                                        \
    F(writev, sys_writev)                                                      \
    F(getsid, sys_getsid)                                                      \
    F(fdatasync, sys_fdatasync)                                                \
    F(_sysctl, sys_ni_syscall)                                                 \
    F(mlock, sys_ni_syscall)                                                   \
    F(munlock, sys_ni_syscall)                                                 \
    F(mlockall, sys_ni_syscall)                                                \
    F(munlockall, sys_ni_syscall)                                              \
    F(sched_setparam, sys_ni_syscall)                                          \
    F(sched_getparam, sys_ni_syscall)                                          \
    F(sched_setscheduler, sys_ni_syscall)                                      \
    F(sched_getscheduler, sys_ni_syscall)                                      \
    F(sched_yield, sys_sched_yield)                                            \
    F(sched_get_priority_max, sys_ni_syscall)                                  \
    F(sched_get_priority_min, sys_ni_syscall)                                  \
    F(sched_rr_get_interval, sys_ni_syscall)                                   \
    F(nanosleep, sys_nanosleep_time32)                                         \
    F(mremap, sys_ni_syscall)                                                  \
    F(setresuid, sys_ni_syscall)                                               \
    F(getresuid, sys_getresuid16)                                              \
    F(vm86, sys_ni_syscall)                                                    \
    F(query_module, sys_ni_syscall)                                            \
    F(poll, sys_poll)                                                          \
    F(nfsservctl, sys_ni_syscall)                                              \
    F(setresgid, sys_ni_syscall)                                               \
    F(getresgid, sys_getresgid16)                                              \
    F(prctl, sys_prctl)                                                        \
    F(rt_sigreturn, sys_rt_sigreturn)                                          \
    F(rt_sigaction, sys_rt_sigaction)                                          \
    F(rt_sigprocmask, sys_rt_sigprocmask)                                      \
    F(rt_sigpending, sys_rt_sigpending)                                        \
    F(rt_sigtimedwait, sys_ni_syscall)                                         \
    F(rt_sigqueueinfo, sys_ni_syscall)                                         \
    F(rt_sigsuspend, sys_rt_sigsuspend)                                        \
    F(pread64, sys_ia32_pread64)                                               \
    F(pwrite64, sys_ia32_pwrite64)                                             \
    F(chown, sys_chown16)                                                      \
    F(getcwd, sys_getcwd)                                                      \
    F(capget, sys_ni_syscall)                                                  \
    F(capset, sys_ni_syscall)                                                  \
    F(sigaltstack, sys_ni_syscall)                                             \
    F(sendfile, sys_ni_syscall)                                                \
    F(getpmsg, sys_ni_syscall)                                                 \
    F(putpmsg, sys_ni_syscall)                                                 \
    F(vfork, sys_vfork)                                                        \
    F(ugetrlimit, sys_ni_syscall)                                              \
    F(mmap2, sys_mmap_pgoff)                                                   \
    F(truncate64, sys_ia32_truncate64)                                         \
    F(ftruncate64, sys_ia32_ftruncate64)                                       \
    F(stat64, sys_stat64)                                                      \
    F(lstat64, sys_lstat64)                                                    \
    F(fstat64, sys_fstat64)                                                    \
    F(lchown32, sys_lchown)                                                    \
    F(getuid32, sys_getuid)                                                    \
    F(getgid32, sys_getgid)                                                    \
    F(geteuid32, sys_geteuid)                                                  \
    F(getegid32, sys_getegid)                                                  \
    F(setreuid32, sys_ni_syscall)                                              \
    F(setregid32, sys_ni_syscall)                                              \
    F(getgroups32, sys_getgroups)                                              \
    F(setgroups32, sys_ni_syscall)                                             \
    F(fchown32, sys_fchown)                                                    \
    F(setresuid32, sys_ni_syscall)                                             \
    F(getresuid32, sys_getresuid)                                              \
    F(setresgid32, sys_ni_syscall)                                             \
    F(getresgid32, sys_getresgid)                                              \
    F(chown32, sys_chown)                                                      \
    F(setuid32, sys_ni_syscall)                                                \
    F(setgid32, sys_ni_syscall)                                                \
    F(setfsuid32, sys_ni_syscall)                                              \
    F(setfsgid32, sys_ni_syscall)                                              \
    F(pivot_root, sys_ni_syscall)                                              \
    F(mincore, sys_ni_syscall)                                                 \
    F(madvise, sys_ni_syscall)                                                 \
    F(getdents64, sys_getdents64)                                              \
    F(fcntl64, sys_fcntl64)                                                    \
    F(gettid, sys_gettid)                                                      \
    F(readahead, sys_ni_syscall)                                               \
    F(setxattr, sys_ni_syscall)                                                \
    F(lsetxattr, sys_ni_syscall)                                               \
    F(fsetxattr, sys_ni_syscall)                                               \
    F(getxattr, sys_ni_syscall)                                                \
    F(lgetxattr, sys_ni_syscall)                                               \
    F(fgetxattr, sys_ni_syscall)                                               \
    F(listxattr, sys_ni_syscall)                                               \
    F(llistxattr, sys_ni_syscall)                                              \
    F(flistxattr, sys_ni_syscall)                                              \
    F(removexattr, sys_ni_syscall)                                             \
    F(lremovexattr, sys_ni_syscall)                                            \
    F(fremovexattr, sys_ni_syscall)                                            \
    F(tkill, sys_tkill)                                                        \
    F(sendfile64, sys_ni_syscall)                                              \
    F(futex, sys_ni_syscall)                                                   \
    F(sched_setaffinity, sys_ni_syscall)                                       \
    F(sched_getaffinity, sys_ni_syscall)                                       \
    F(set_thread_area, sys_set_thread_area)                                    \
    F(get_thread_area, sys_get_thread_area)                                    \
    F(io_setup, sys_ni_syscall)                                                \
    F(io_destroy, sys_ni_syscall)                                              \
    F(io_getevents, sys_ni_syscall)                                            \
    F(io_submit, sys_ni_syscall)                                               \
    F(io_cancel, sys_ni_syscall)                                               \
    F(fadvise64, sys_ni_syscall)                                               \
    F(exit_group, sys_exit_group)                                              \
    F(lookup_dcookie, sys_ni_syscall)                                          \
    F(epoll_create, sys_ni_syscall)                                            \
    F(epoll_ctl, sys_ni_syscall)                                               \
    F(epoll_wait, sys_ni_syscall)                                              \
    F(remap_file_pages, sys_ni_syscall)                                        \
    F(set_tid_address, sys_ni_syscall)                                         \
    F(timer_create, sys_ni_syscall)                                            \
    F(timer_settime, sys_ni_syscall)                                           \
    F(timer_gettime, sys_ni_syscall)                                           \
    F(timer_getoverrun, sys_ni_syscall)                                        \
    F(timer_delete, sys_ni_syscall)                                            \
    F(clock_settime, sys_clock_settime32)                                      \
    F(clock_gettime, sys_clock_gettime32)                                      \
    F(clock_getres, sys_clock_getres_time32)                                   \
    F(clock_nanosleep, sys_clock_nanosleep_time32)                             \
    F(statfs64, sys_ni_syscall)                                                \
    F(fstatfs64, sys_ni_syscall)                                               \
    F(tgkill, sys_tgkill)                                                      \
    F(utimes, sys_ni_syscall)                                                  \
    F(fadvise64_64, sys_ni_syscall)                                            \
    F(vserver, sys_ni_syscall)                                                 \
    F(mbind, sys_ni_syscall)                                                   \
    F(get_mempolicy, sys_ni_syscall)                                           \
    F(set_mempolicy, sys_ni_syscall)                                           \
    F(mq_open, sys_ni_syscall)                                                 \
    F(mq_unlink, sys_ni_syscall)                                               \
    F(mq_timedsend, sys_ni_syscall)                                            \
    F(mq_timedreceive, sys_ni_syscall)                                         \
    F(mq_notify, sys_ni_syscall)                                               \
    F(mq_getsetattr, sys_ni_syscall)                                           \
    F(kexec_load, sys_ni_syscall)                                              \
    F(waitid, sys_ni_syscall)                                                  \
    F(add_key, sys_ni_syscall)                                                 \
    F(request_key, sys_ni_syscall)                                             \
    F(keyctl, sys_ni_syscall)                                                  \
    F(ioprio_set, sys_ni_syscall)                                              \
    F(ioprio_get, sys_ni_syscall)                                              \
    F(inotify_init, sys_ni_syscall)                                            \
    F(inotify_add_watch, sys_ni_syscall)                                       \
    F(inotify_rm_watch, sys_ni_syscall)                                        \
    F(migrate_pages, sys_ni_syscall)                                           \
    F(openat, sys_openat)                                                      \
    F(mkdirat, sys_mkdirat)                                                    \
    F(mknodat, sys_mknodat)                                                    \
    F(fchownat, sys_fchownat)                                                  \
    F(futimesat, sys_ni_syscall)                                               \
    F(fstatat64, sys_fstatat64)                                                \
    F(unlinkat, sys_unlinkat)                                                  \
    F(renameat, sys_renameat)                                                  \
    F(linkat, sys_linkat)                                                      \
    F(symlinkat, sys_symlinkat)                                                \
    F(readlinkat, sys_readlinkat)                                              \
    F(fchmodat, sys_fchmodat)                                                  \
    F(faccessat, sys_faccessat)                                                \
    F(pselect6, sys_pselect6_time32)                                           \
    F(ppoll, sys_ppoll_time32)                                                 \
    F(unshare, sys_unshare)                                                    \
    F(set_robust_list, sys_ni_syscall)                                         \
    F(get_robust_list, sys_ni_syscall)                                         \
    F(splice, sys_ni_syscall)                                                  \
    F(sync_file_range, sys_ni_syscall)                                         \
    F(tee, sys_ni_syscall)                                                     \
    F(vmsplice, sys_ni_syscall)                                                \
    F(move_pages, sys_ni_syscall)                                              \
    F(getcpu, sys_getcpu)                                                      \
    F(epoll_pwait, sys_ni_syscall)                                             \
    F(utimensat, sys_ni_syscall)                                               \
    F(signalfd, sys_ni_syscall)                                                \
    F(timerfd_create, sys_ni_syscall)                                          \
    F(eventfd, sys_ni_syscall)                                                 \
    F(fallocate, sys_ni_syscall)                                               \
    F(timerfd_settime, sys_ni_syscall)                                         \
    F(timerfd_gettime, sys_ni_syscall)                                         \
    F(signalfd4, sys_ni_syscall)                                               \
    F(eventfd2, sys_ni_syscall)                                                \
    F(epoll_create1, sys_ni_syscall)                                           \
    F(dup3, sys_dup3)                                                          \
    F(pipe2, sys_pipe2)                                                        \
    F(inotify_init1, sys_ni_syscall)                                           \
    F(preadv, sys_preadv)                                                      \
    F(pwritev, sys_pwritev)                                                    \
    F(rt_tgsigqueueinfo, sys_ni_syscall)                                       \
    F(perf_event_open, sys_ni_syscall)                                         \
    F(recvmmsg, sys_ni_syscall)                                                \
    F(fanotify_init, sys_ni_syscall)                                           \
    F(fanotify_mark, sys_ni_syscall)                                           \
    F(prlimit64, sys_ni_syscall)                                               \
    F(name_to_handle_at, sys_ni_syscall)                                       \
    F(open_by_handle_at, sys_ni_syscall)                                       \
    F(clock_adjtime, sys_ni_syscall)                                           \
    F(syncfs, sys_syncfs)                                                      \
    F(sendmmsg, sys_ni_syscall)                                                \
    F(setns, sys_ni_syscall)                                                   \
    F(process_vm_readv, sys_process_vm_readv)                                  \
    F(process_vm_writev, sys_process_vm_writev)                                \
    F(kcmp, sys_ni_syscall)                                                    \
    F(finit_module, sys_ni_syscall)                                            \
    F(sched_setattr, sys_ni_syscall)                                           \
    F(sched_getattr, sys_ni_syscall)                                           \
    F(renameat2, sys_renameat2)                                                \
    F(seccomp, sys_ni_syscall)                                                 \
    F(getrandom, sys_getrandom)                                                \
    F(memfd_create, sys_ni_syscall)                                            \
    F(bpf, sys_ni_syscall)                                                     \
    F(execveat, sys_ni_syscall)                                                \
    F(socket, sys_socket)                                                      \
    F(socketpair, sys_ni_syscall)                                              \
    F(bind, sys_bind)                                                          \
    F(connect, sys_connect)                                                    \
    F(listen, sys_listen)                                                      \
    F(accept4, sys_accept4)                                                    \
    F(getsockopt, sys_ni_syscall)                                              \
    F(setsockopt, sys_ni_syscall)                                              \
    F(getsockname, sys_ni_syscall)                                             \
    F(getpeername, sys_ni_syscall)                                             \
    F(sendto, sys_ni_syscall)                                                  \
    F(sendmsg, sys_ni_syscall)                                                 \
    F(recvfrom, sys_ni_syscall)                                                \
    F(recvmsg, sys_ni_syscall)                                                 \
    F(shutdown, sys_shutdown)                                                  \
    F(userfaultfd, sys_ni_syscall)                                             \
    F(membarrier, sys_ni_syscall)                                              \
    F(mlock2, sys_ni_syscall)                                                  \
    F(copy_file_range, sys_ni_syscall)                                         \
    F(preadv2, sys_preadv2)                                                    \
    F(pwritev2, sys_pwritev2)                                                  \
    F(pkey_mprotect, sys_ni_syscall)                                           \
    F(pkey_alloc, sys_ni_syscall)                                              \
    F(pkey_free, sys_ni_syscall)                                               \
    F(statx, sys_statx)                                                        \
    F(arch_prctl, sys_arch_prctl)                                              \
    F(io_pgetevents, sys_ni_syscall)                                           \
    F(rseq, sys_ni_syscall)                                                    \
    F(semget, sys_ni_syscall)                                                  \
    F(semctl, sys_ni_syscall)                                                  \
    F(shmget, sys_ni_syscall)                                                  \
    F(shmctl, sys_ni_syscall)                                                  \
    F(shmat, sys_ni_syscall)                                                   \
    F(shmdt, sys_ni_syscall)                                                   \
    F(msgget, sys_ni_syscall)                                                  \
    F(msgsnd, sys_ni_syscall)                                                  \
    F(msgrcv, sys_ni_syscall)                                                  \
    F(msgctl, sys_ni_syscall)                                                  \
    F(clock_gettime64, sys_clock_gettime)                                      \
    F(clock_settime64, sys_clock_settime)                                      \
    F(clock_adjtime64, sys_ni_syscall)                                         \
    F(clock_getres_time64, sys_clock_getres)                                   \
    F(clock_nanosleep_time64, sys_clock_nanosleep)                             \
    F(timer_gettime64, sys_ni_syscall)                                         \
    F(timer_settime64, sys_ni_syscall)                                         \
    F(timerfd_gettime64, sys_ni_syscall)                                       \
    F(timerfd_settime64, sys_ni_syscall)                                       \
    F(utimensat_time64, sys_ni_syscall)                                        \
    F(pselect6_time64, sys_pselect6)                                           \
    F(ppoll_time64, sys_ppoll)                                                 \
    F(io_pgetevents_time64, sys_ni_syscall)                                    \
    F(recvmmsg_time64, sys_ni_syscall)                                         \
    F(mq_timedsend_time64, sys_ni_syscall)                                     \
    F(mq_timedreceive_time64, sys_ni_syscall)                                  \
    F(semtimedop_time64, sys_ni_syscall)                                       \
    F(rt_sigtimedwait_time64, sys_ni_syscall)                                  \
    F(futex_time64, sys_ni_syscall)                                            \
    F(sched_rr_get_interval_time64, sys_ni_syscall)                            \
    F(pidfd_send_signal, sys_ni_syscall)                                       \
    F(io_uring_setup, sys_ni_syscall)                                          \
    F(io_uring_enter, sys_ni_syscall)                                          \
    F(io_uring_register, sys_ni_syscall)                                       \
    F(dbgprint, sys_dbgprint)

SYSCALL_RAW(int80_clone, regs) {
    unsigned long flags = regs->bx;
    void* stack = (void*)regs->cx;
    pid_t* parent_tid = (pid_t*)regs->dx;
    void* tls = (void*)regs->si;
    pid_t* child_tid = (pid_t*)regs->di;
    return clone_user_task(regs, flags, stack, parent_tid, child_tid, tls);
}

static const struct syscall syscalls[] = {
#define F(name, handler)                                                       \
    [SYS_##name] = {                                                           \
        #name,                                                                 \
        (handler),                                                             \
    },
    ENUMERATE_SYSCALLS(F)
#undef F
};

static void decode(const struct registers* regs, unsigned long* out_number,
                   unsigned long out_args[6]) {
    if (out_number)
        *out_number = regs->ax;
    if (out_args) {
        out_args[0] = regs->bx;
        out_args[1] = regs->cx;
        out_args[2] = regs->dx;
        out_args[3] = regs->si;
        out_args[4] = regs->di;
        out_args[5] = regs->bp;
    }
}

static void set_return_value(struct registers* regs, unsigned long value) {
    regs->ax = value;
}

static void restart(struct registers* regs) {
    regs->ip -= 2; // Re-execute `int $SYSCALL_VECTOR`
}

static const struct syscall_abi abi = {
    .table = syscalls,
    .table_len = ARRAY_SIZE(syscalls),
    .decode = decode,
    .set_return_value = set_return_value,
    .restart = restart,
};

static void handler(struct registers* regs) {
    ASSERT((regs->cs & 3) == 3);
    ASSERT((regs->ss & 3) == 3);
    SCOPED_ENABLE_INTERRUPTS();
    syscall_handle(&abi, regs);
}

void syscall_init_int80(void) {
    arch_interrupts_set_handler(SYSCALL_VECTOR, handler);
    idt_set_gate_user_callable(SYSCALL_VECTOR);
    idt_flush();
}
