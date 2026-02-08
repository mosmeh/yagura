#include <kernel/api/sys/syscall.h>
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
    F(restart_syscall, sys_ni_syscall, 0)                                      \
    F(exit, sys_exit, 0)                                                       \
    F(fork, sys_fork, SYSCALL_RAW_REGISTERS)                                   \
    F(read, sys_read, 0)                                                       \
    F(write, sys_write, 0)                                                     \
    F(open, sys_open, 0)                                                       \
    F(close, sys_close, 0)                                                     \
    F(waitpid, sys_waitpid, 0)                                                 \
    F(creat, sys_creat, 0)                                                     \
    F(link, sys_link, 0)                                                       \
    F(unlink, sys_unlink, 0)                                                   \
    F(execve, sys_execve, 0)                                                   \
    F(chdir, sys_chdir, 0)                                                     \
    F(time, sys_time32, 0)                                                     \
    F(mknod, sys_mknod, 0)                                                     \
    F(chmod, sys_chmod, 0)                                                     \
    F(lchown, sys_lchown16, 0)                                                 \
    F(break, sys_ni_syscall, 0)                                                \
    F(oldstat, sys_stat, 0)                                                    \
    F(lseek, sys_lseek, 0)                                                     \
    F(getpid, sys_getpid, 0)                                                   \
    F(mount, sys_mount, 0)                                                     \
    F(umount, sys_ni_syscall, 0)                                               \
    F(setuid, sys_ni_syscall, 0)                                               \
    F(getuid, sys_getuid16, 0)                                                 \
    F(stime, sys_stime32, 0)                                                   \
    F(ptrace, sys_ni_syscall, 0)                                               \
    F(alarm, sys_ni_syscall, 0)                                                \
    F(oldfstat, sys_fstat, 0)                                                  \
    F(pause, sys_pause, 0)                                                     \
    F(utime, sys_ni_syscall, 0)                                                \
    F(stty, sys_ni_syscall, 0)                                                 \
    F(gtty, sys_ni_syscall, 0)                                                 \
    F(access, sys_access, 0)                                                   \
    F(nice, sys_ni_syscall, 0)                                                 \
    F(ftime, sys_ni_syscall, 0)                                                \
    F(sync, sys_sync, 0)                                                       \
    F(kill, sys_kill, 0)                                                       \
    F(rename, sys_rename, 0)                                                   \
    F(mkdir, sys_mkdir, 0)                                                     \
    F(rmdir, sys_rmdir, 0)                                                     \
    F(dup, sys_dup, 0)                                                         \
    F(pipe, sys_pipe, 0)                                                       \
    F(times, sys_times, 0)                                                     \
    F(prof, sys_ni_syscall, 0)                                                 \
    F(brk, sys_ni_syscall, 0)                                                  \
    F(setgid, sys_ni_syscall, 0)                                               \
    F(getgid, sys_getgid16, 0)                                                 \
    F(signal, sys_signal, 0)                                                   \
    F(geteuid, sys_geteuid16, 0)                                               \
    F(getegid, sys_getegid16, 0)                                               \
    F(acct, sys_ni_syscall, 0)                                                 \
    F(umount2, sys_ni_syscall, 0)                                              \
    F(lock, sys_ni_syscall, 0)                                                 \
    F(ioctl, sys_ioctl, 0)                                                     \
    F(fcntl, sys_fcntl, 0)                                                     \
    F(mpx, sys_ni_syscall, 0)                                                  \
    F(setpgid, sys_setpgid, 0)                                                 \
    F(ulimit, sys_ni_syscall, 0)                                               \
    F(oldolduname, sys_olduname, 0)                                            \
    F(umask, sys_umask, 0)                                                     \
    F(chroot, sys_chroot, 0)                                                   \
    F(ustat, sys_ni_syscall, 0)                                                \
    F(dup2, sys_dup2, 0)                                                       \
    F(getppid, sys_getppid, 0)                                                 \
    F(getpgrp, sys_getpgrp, 0)                                                 \
    F(setsid, sys_ni_syscall, 0)                                               \
    F(sigaction, sys_sigaction, 0)                                             \
    F(sgetmask, sys_sgetmask, 0)                                               \
    F(ssetmask, sys_ssetmask, 0)                                               \
    F(setreuid, sys_ni_syscall, 0)                                             \
    F(setregid, sys_ni_syscall, 0)                                             \
    F(sigsuspend, sys_sigsuspend, 0)                                           \
    F(sigpending, sys_sigpending, 0)                                           \
    F(sethostname, sys_sethostname, 0)                                         \
    F(setrlimit, sys_ni_syscall, 0)                                            \
    F(getrlimit, sys_ni_syscall, 0)                                            \
    F(getrusage, sys_ni_syscall, 0)                                            \
    F(gettimeofday, sys_gettimeofday, 0)                                       \
    F(settimeofday, sys_settimeofday, 0)                                       \
    F(getgroups, sys_getgroups16, 0)                                           \
    F(setgroups, sys_ni_syscall, 0)                                            \
    F(select, sys_old_select, 0)                                               \
    F(symlink, sys_symlink, 0)                                                 \
    F(oldlstat, sys_lstat, 0)                                                  \
    F(readlink, sys_readlink, 0)                                               \
    F(uselib, sys_ni_syscall, 0)                                               \
    F(swapon, sys_ni_syscall, 0)                                               \
    F(reboot, sys_reboot, 0)                                                   \
    F(readdir, sys_old_readdir, 0)                                             \
    F(mmap, sys_old_mmap, 0)                                                   \
    F(munmap, sys_munmap, 0)                                                   \
    F(truncate, sys_truncate, 0)                                               \
    F(ftruncate, sys_ftruncate, 0)                                             \
    F(fchmod, sys_fchmod, 0)                                                   \
    F(fchown, sys_fchown16, 0)                                                 \
    F(getpriority, sys_ni_syscall, 0)                                          \
    F(setpriority, sys_ni_syscall, 0)                                          \
    F(profil, sys_ni_syscall, 0)                                               \
    F(statfs, sys_ni_syscall, 0)                                               \
    F(fstatfs, sys_ni_syscall, 0)                                              \
    F(ioperm, sys_ni_syscall, 0)                                               \
    F(socketcall, sys_ni_syscall, 0)                                           \
    F(syslog, sys_ni_syscall, 0)                                               \
    F(setitimer, sys_ni_syscall, 0)                                            \
    F(getitimer, sys_ni_syscall, 0)                                            \
    F(stat, sys_newstat, 0)                                                    \
    F(lstat, sys_newlstat, 0)                                                  \
    F(fstat, sys_newfstat, 0)                                                  \
    F(olduname, sys_uname, 0)                                                  \
    F(iopl, sys_ni_syscall, 0)                                                 \
    F(vhangup, sys_ni_syscall, 0)                                              \
    F(idle, sys_ni_syscall, 0)                                                 \
    F(vm86old, sys_ni_syscall, 0)                                              \
    F(wait4, sys_wait4, 0)                                                     \
    F(swapoff, sys_ni_syscall, 0)                                              \
    F(sysinfo, sys_sysinfo, 0)                                                 \
    F(ipc, sys_ni_syscall, 0)                                                  \
    F(fsync, sys_fsync, 0)                                                     \
    F(sigreturn, sys_sigreturn, SYSCALL_RAW_REGISTERS | SYSCALL_NO_ERROR)      \
    F(clone, sys_clone, SYSCALL_RAW_REGISTERS)                                 \
    F(setdomainname, sys_setdomainname, 0)                                     \
    F(uname, sys_newuname, 0)                                                  \
    F(modify_ldt, sys_ni_syscall, 0)                                           \
    F(adjtimex, sys_ni_syscall, 0)                                             \
    F(mprotect, sys_mprotect, 0)                                               \
    F(sigprocmask, sys_sigprocmask, 0)                                         \
    F(create_module, sys_ni_syscall, 0)                                        \
    F(init_module, sys_ni_syscall, 0)                                          \
    F(delete_module, sys_ni_syscall, 0)                                        \
    F(get_kernel_syms, sys_ni_syscall, 0)                                      \
    F(quotactl, sys_ni_syscall, 0)                                             \
    F(getpgid, sys_getpgid, 0)                                                 \
    F(fchdir, sys_fchdir, 0)                                                   \
    F(bdflush, sys_ni_syscall, 0)                                              \
    F(sysfs, sys_ni_syscall, 0)                                                \
    F(personality, sys_ni_syscall, 0)                                          \
    F(afs_syscall, sys_ni_syscall, 0)                                          \
    F(setfsuid, sys_ni_syscall, 0)                                             \
    F(setfsgid, sys_ni_syscall, 0)                                             \
    F(_llseek, sys_llseek, 0)                                                  \
    F(getdents, sys_getdents, 0)                                               \
    F(_newselect, sys_select, 0)                                               \
    F(flock, sys_ni_syscall, 0)                                                \
    F(msync, sys_msync, 0)                                                     \
    F(readv, sys_readv, 0)                                                     \
    F(writev, sys_writev, 0)                                                   \
    F(getsid, sys_getsid, 0)                                                   \
    F(fdatasync, sys_fdatasync, 0)                                             \
    F(_sysctl, sys_ni_syscall, 0)                                              \
    F(mlock, sys_ni_syscall, 0)                                                \
    F(munlock, sys_ni_syscall, 0)                                              \
    F(mlockall, sys_ni_syscall, 0)                                             \
    F(munlockall, sys_ni_syscall, 0)                                           \
    F(sched_setparam, sys_ni_syscall, 0)                                       \
    F(sched_getparam, sys_ni_syscall, 0)                                       \
    F(sched_setscheduler, sys_ni_syscall, 0)                                   \
    F(sched_getscheduler, sys_ni_syscall, 0)                                   \
    F(sched_yield, sys_sched_yield, 0)                                         \
    F(sched_get_priority_max, sys_ni_syscall, 0)                               \
    F(sched_get_priority_min, sys_ni_syscall, 0)                               \
    F(sched_rr_get_interval, sys_ni_syscall, 0)                                \
    F(nanosleep, sys_nanosleep_time32, 0)                                      \
    F(mremap, sys_ni_syscall, 0)                                               \
    F(setresuid, sys_ni_syscall, 0)                                            \
    F(getresuid, sys_getresuid16, 0)                                           \
    F(vm86, sys_ni_syscall, 0)                                                 \
    F(query_module, sys_ni_syscall, 0)                                         \
    F(poll, sys_poll, 0)                                                       \
    F(nfsservctl, sys_ni_syscall, 0)                                           \
    F(setresgid, sys_ni_syscall, 0)                                            \
    F(getresgid, sys_getresgid16, 0)                                           \
    F(prctl, sys_prctl, 0)                                                     \
    F(rt_sigreturn, sys_rt_sigreturn,                                          \
      SYSCALL_RAW_REGISTERS | SYSCALL_NO_ERROR)                                \
    F(rt_sigaction, sys_rt_sigaction, 0)                                       \
    F(rt_sigprocmask, sys_rt_sigprocmask, 0)                                   \
    F(rt_sigpending, sys_rt_sigpending, 0)                                     \
    F(rt_sigtimedwait, sys_ni_syscall, 0)                                      \
    F(rt_sigqueueinfo, sys_ni_syscall, 0)                                      \
    F(rt_sigsuspend, sys_rt_sigsuspend, 0)                                     \
    F(pread64, sys_ia32_pread64, 0)                                            \
    F(pwrite64, sys_ia32_pwrite64, 0)                                          \
    F(chown, sys_chown16, 0)                                                   \
    F(getcwd, sys_getcwd, 0)                                                   \
    F(capget, sys_ni_syscall, 0)                                               \
    F(capset, sys_ni_syscall, 0)                                               \
    F(sigaltstack, sys_ni_syscall, 0)                                          \
    F(sendfile, sys_ni_syscall, 0)                                             \
    F(getpmsg, sys_ni_syscall, 0)                                              \
    F(putpmsg, sys_ni_syscall, 0)                                              \
    F(vfork, sys_vfork, SYSCALL_RAW_REGISTERS)                                 \
    F(ugetrlimit, sys_ni_syscall, 0)                                           \
    F(mmap2, sys_mmap_pgoff, 0)                                                \
    F(truncate64, sys_ia32_truncate64, 0)                                      \
    F(ftruncate64, sys_ia32_ftruncate64, 0)                                    \
    F(stat64, sys_stat64, 0)                                                   \
    F(lstat64, sys_lstat64, 0)                                                 \
    F(fstat64, sys_fstat64, 0)                                                 \
    F(lchown32, sys_lchown, 0)                                                 \
    F(getuid32, sys_getuid, 0)                                                 \
    F(getgid32, sys_getgid, 0)                                                 \
    F(geteuid32, sys_geteuid, 0)                                               \
    F(getegid32, sys_getegid, 0)                                               \
    F(setreuid32, sys_ni_syscall, 0)                                           \
    F(setregid32, sys_ni_syscall, 0)                                           \
    F(getgroups32, sys_getgroups, 0)                                           \
    F(setgroups32, sys_ni_syscall, 0)                                          \
    F(fchown32, sys_fchown, 0)                                                 \
    F(setresuid32, sys_ni_syscall, 0)                                          \
    F(getresuid32, sys_getresuid, 0)                                           \
    F(setresgid32, sys_ni_syscall, 0)                                          \
    F(getresgid32, sys_getresgid, 0)                                           \
    F(chown32, sys_chown, 0)                                                   \
    F(setuid32, sys_ni_syscall, 0)                                             \
    F(setgid32, sys_ni_syscall, 0)                                             \
    F(setfsuid32, sys_ni_syscall, 0)                                           \
    F(setfsgid32, sys_ni_syscall, 0)                                           \
    F(pivot_root, sys_ni_syscall, 0)                                           \
    F(mincore, sys_ni_syscall, 0)                                              \
    F(madvise, sys_ni_syscall, 0)                                              \
    F(getdents64, sys_getdents64, 0)                                           \
    F(fcntl64, sys_fcntl64, 0)                                                 \
    F(gettid, sys_gettid, 0)                                                   \
    F(readahead, sys_ni_syscall, 0)                                            \
    F(setxattr, sys_ni_syscall, 0)                                             \
    F(lsetxattr, sys_ni_syscall, 0)                                            \
    F(fsetxattr, sys_ni_syscall, 0)                                            \
    F(getxattr, sys_ni_syscall, 0)                                             \
    F(lgetxattr, sys_ni_syscall, 0)                                            \
    F(fgetxattr, sys_ni_syscall, 0)                                            \
    F(listxattr, sys_ni_syscall, 0)                                            \
    F(llistxattr, sys_ni_syscall, 0)                                           \
    F(flistxattr, sys_ni_syscall, 0)                                           \
    F(removexattr, sys_ni_syscall, 0)                                          \
    F(lremovexattr, sys_ni_syscall, 0)                                         \
    F(fremovexattr, sys_ni_syscall, 0)                                         \
    F(tkill, sys_tkill, 0)                                                     \
    F(sendfile64, sys_ni_syscall, 0)                                           \
    F(futex, sys_ni_syscall, 0)                                                \
    F(sched_setaffinity, sys_ni_syscall, 0)                                    \
    F(sched_getaffinity, sys_ni_syscall, 0)                                    \
    F(set_thread_area, sys_set_thread_area, 0)                                 \
    F(get_thread_area, sys_get_thread_area, 0)                                 \
    F(io_setup, sys_ni_syscall, 0)                                             \
    F(io_destroy, sys_ni_syscall, 0)                                           \
    F(io_getevents, sys_ni_syscall, 0)                                         \
    F(io_submit, sys_ni_syscall, 0)                                            \
    F(io_cancel, sys_ni_syscall, 0)                                            \
    F(fadvise64, sys_ni_syscall, 0)                                            \
    F(exit_group, sys_exit_group, 0)                                           \
    F(lookup_dcookie, sys_ni_syscall, 0)                                       \
    F(epoll_create, sys_ni_syscall, 0)                                         \
    F(epoll_ctl, sys_ni_syscall, 0)                                            \
    F(epoll_wait, sys_ni_syscall, 0)                                           \
    F(remap_file_pages, sys_ni_syscall, 0)                                     \
    F(set_tid_address, sys_ni_syscall, 0)                                      \
    F(timer_create, sys_ni_syscall, 0)                                         \
    F(timer_settime, sys_ni_syscall, 0)                                        \
    F(timer_gettime, sys_ni_syscall, 0)                                        \
    F(timer_getoverrun, sys_ni_syscall, 0)                                     \
    F(timer_delete, sys_ni_syscall, 0)                                         \
    F(clock_settime, sys_clock_settime32, 0)                                   \
    F(clock_gettime, sys_clock_gettime32, 0)                                   \
    F(clock_getres, sys_clock_getres_time32, 0)                                \
    F(clock_nanosleep, sys_clock_nanosleep_time32, 0)                          \
    F(statfs64, sys_ni_syscall, 0)                                             \
    F(fstatfs64, sys_ni_syscall, 0)                                            \
    F(tgkill, sys_tgkill, 0)                                                   \
    F(utimes, sys_ni_syscall, 0)                                               \
    F(fadvise64_64, sys_ni_syscall, 0)                                         \
    F(vserver, sys_ni_syscall, 0)                                              \
    F(mbind, sys_ni_syscall, 0)                                                \
    F(get_mempolicy, sys_ni_syscall, 0)                                        \
    F(set_mempolicy, sys_ni_syscall, 0)                                        \
    F(mq_open, sys_ni_syscall, 0)                                              \
    F(mq_unlink, sys_ni_syscall, 0)                                            \
    F(mq_timedsend, sys_ni_syscall, 0)                                         \
    F(mq_timedreceive, sys_ni_syscall, 0)                                      \
    F(mq_notify, sys_ni_syscall, 0)                                            \
    F(mq_getsetattr, sys_ni_syscall, 0)                                        \
    F(kexec_load, sys_ni_syscall, 0)                                           \
    F(waitid, sys_ni_syscall, 0)                                               \
    F(add_key, sys_ni_syscall, 0)                                              \
    F(request_key, sys_ni_syscall, 0)                                          \
    F(keyctl, sys_ni_syscall, 0)                                               \
    F(ioprio_set, sys_ni_syscall, 0)                                           \
    F(ioprio_get, sys_ni_syscall, 0)                                           \
    F(inotify_init, sys_ni_syscall, 0)                                         \
    F(inotify_add_watch, sys_ni_syscall, 0)                                    \
    F(inotify_rm_watch, sys_ni_syscall, 0)                                     \
    F(migrate_pages, sys_ni_syscall, 0)                                        \
    F(openat, sys_openat, 0)                                                   \
    F(mkdirat, sys_mkdirat, 0)                                                 \
    F(mknodat, sys_mknodat, 0)                                                 \
    F(fchownat, sys_fchownat, 0)                                               \
    F(futimesat, sys_ni_syscall, 0)                                            \
    F(fstatat64, sys_fstatat64, 0)                                             \
    F(unlinkat, sys_unlinkat, 0)                                               \
    F(renameat, sys_renameat, 0)                                               \
    F(linkat, sys_linkat, 0)                                                   \
    F(symlinkat, sys_symlinkat, 0)                                             \
    F(readlinkat, sys_readlinkat, 0)                                           \
    F(fchmodat, sys_fchmodat, 0)                                               \
    F(faccessat, sys_faccessat, 0)                                             \
    F(pselect6, sys_pselect6_time32, 0)                                        \
    F(ppoll, sys_ppoll_time32, 0)                                              \
    F(unshare, sys_ni_syscall, 0)                                              \
    F(set_robust_list, sys_ni_syscall, 0)                                      \
    F(get_robust_list, sys_ni_syscall, 0)                                      \
    F(splice, sys_ni_syscall, 0)                                               \
    F(sync_file_range, sys_ni_syscall, 0)                                      \
    F(tee, sys_ni_syscall, 0)                                                  \
    F(vmsplice, sys_ni_syscall, 0)                                             \
    F(move_pages, sys_ni_syscall, 0)                                           \
    F(getcpu, sys_getcpu, 0)                                                   \
    F(epoll_pwait, sys_ni_syscall, 0)                                          \
    F(utimensat, sys_ni_syscall, 0)                                            \
    F(signalfd, sys_ni_syscall, 0)                                             \
    F(timerfd_create, sys_ni_syscall, 0)                                       \
    F(eventfd, sys_ni_syscall, 0)                                              \
    F(fallocate, sys_ni_syscall, 0)                                            \
    F(timerfd_settime, sys_ni_syscall, 0)                                      \
    F(timerfd_gettime, sys_ni_syscall, 0)                                      \
    F(signalfd4, sys_ni_syscall, 0)                                            \
    F(eventfd2, sys_ni_syscall, 0)                                             \
    F(epoll_create1, sys_ni_syscall, 0)                                        \
    F(dup3, sys_dup3, 0)                                                       \
    F(pipe2, sys_pipe2, 0)                                                     \
    F(inotify_init1, sys_ni_syscall, 0)                                        \
    F(preadv, sys_preadv, 0)                                                   \
    F(pwritev, sys_pwritev, 0)                                                 \
    F(rt_tgsigqueueinfo, sys_ni_syscall, 0)                                    \
    F(perf_event_open, sys_ni_syscall, 0)                                      \
    F(recvmmsg, sys_ni_syscall, 0)                                             \
    F(fanotify_init, sys_ni_syscall, 0)                                        \
    F(fanotify_mark, sys_ni_syscall, 0)                                        \
    F(prlimit64, sys_ni_syscall, 0)                                            \
    F(name_to_handle_at, sys_ni_syscall, 0)                                    \
    F(open_by_handle_at, sys_ni_syscall, 0)                                    \
    F(clock_adjtime, sys_ni_syscall, 0)                                        \
    F(syncfs, sys_syncfs, 0)                                                   \
    F(sendmmsg, sys_ni_syscall, 0)                                             \
    F(setns, sys_ni_syscall, 0)                                                \
    F(process_vm_readv, sys_process_vm_readv, 0)                               \
    F(process_vm_writev, sys_process_vm_writev, 0)                             \
    F(kcmp, sys_ni_syscall, 0)                                                 \
    F(finit_module, sys_ni_syscall, 0)                                         \
    F(sched_setattr, sys_ni_syscall, 0)                                        \
    F(sched_getattr, sys_ni_syscall, 0)                                        \
    F(renameat2, sys_renameat2, 0)                                             \
    F(seccomp, sys_ni_syscall, 0)                                              \
    F(getrandom, sys_getrandom, 0)                                             \
    F(memfd_create, sys_ni_syscall, 0)                                         \
    F(bpf, sys_ni_syscall, 0)                                                  \
    F(execveat, sys_ni_syscall, 0)                                             \
    F(socket, sys_socket, 0)                                                   \
    F(socketpair, sys_ni_syscall, 0)                                           \
    F(bind, sys_bind, 0)                                                       \
    F(connect, sys_connect, 0)                                                 \
    F(listen, sys_listen, 0)                                                   \
    F(accept4, sys_accept4, 0)                                                 \
    F(getsockopt, sys_ni_syscall, 0)                                           \
    F(setsockopt, sys_ni_syscall, 0)                                           \
    F(getsockname, sys_ni_syscall, 0)                                          \
    F(getpeername, sys_ni_syscall, 0)                                          \
    F(sendto, sys_ni_syscall, 0)                                               \
    F(sendmsg, sys_ni_syscall, 0)                                              \
    F(recvfrom, sys_ni_syscall, 0)                                             \
    F(recvmsg, sys_ni_syscall, 0)                                              \
    F(shutdown, sys_shutdown, 0)                                               \
    F(userfaultfd, sys_ni_syscall, 0)                                          \
    F(membarrier, sys_ni_syscall, 0)                                           \
    F(mlock2, sys_ni_syscall, 0)                                               \
    F(copy_file_range, sys_ni_syscall, 0)                                      \
    F(preadv2, sys_preadv2, 0)                                                 \
    F(pwritev2, sys_pwritev2, 0)                                               \
    F(pkey_mprotect, sys_ni_syscall, 0)                                        \
    F(pkey_alloc, sys_ni_syscall, 0)                                           \
    F(pkey_free, sys_ni_syscall, 0)                                            \
    F(statx, sys_statx, 0)                                                     \
    F(arch_prctl, sys_arch_prctl, 0)                                           \
    F(io_pgetevents, sys_ni_syscall, 0)                                        \
    F(rseq, sys_ni_syscall, 0)                                                 \
    F(semget, sys_ni_syscall, 0)                                               \
    F(semctl, sys_ni_syscall, 0)                                               \
    F(shmget, sys_ni_syscall, 0)                                               \
    F(shmctl, sys_ni_syscall, 0)                                               \
    F(shmat, sys_ni_syscall, 0)                                                \
    F(shmdt, sys_ni_syscall, 0)                                                \
    F(msgget, sys_ni_syscall, 0)                                               \
    F(msgsnd, sys_ni_syscall, 0)                                               \
    F(msgrcv, sys_ni_syscall, 0)                                               \
    F(msgctl, sys_ni_syscall, 0)                                               \
    F(clock_gettime64, sys_clock_gettime, 0)                                   \
    F(clock_settime64, sys_clock_settime, 0)                                   \
    F(clock_adjtime64, sys_ni_syscall, 0)                                      \
    F(clock_getres_time64, sys_clock_getres, 0)                                \
    F(clock_nanosleep_time64, sys_clock_nanosleep, 0)                          \
    F(timer_gettime64, sys_ni_syscall, 0)                                      \
    F(timer_settime64, sys_ni_syscall, 0)                                      \
    F(timerfd_gettime64, sys_ni_syscall, 0)                                    \
    F(timerfd_settime64, sys_ni_syscall, 0)                                    \
    F(utimensat_time64, sys_ni_syscall, 0)                                     \
    F(pselect6_time64, sys_pselect6, 0)                                        \
    F(ppoll_time64, sys_ppoll, 0)                                              \
    F(io_pgetevents_time64, sys_ni_syscall, 0)                                 \
    F(recvmmsg_time64, sys_ni_syscall, 0)                                      \
    F(mq_timedsend_time64, sys_ni_syscall, 0)                                  \
    F(mq_timedreceive_time64, sys_ni_syscall, 0)                               \
    F(semtimedop_time64, sys_ni_syscall, 0)                                    \
    F(rt_sigtimedwait_time64, sys_ni_syscall, 0)                               \
    F(futex_time64, sys_ni_syscall, 0)                                         \
    F(sched_rr_get_interval_time64, sys_ni_syscall, 0)                         \
    F(pidfd_send_signal, sys_ni_syscall, 0)                                    \
    F(io_uring_setup, sys_ni_syscall, 0)                                       \
    F(io_uring_enter, sys_ni_syscall, 0)                                       \
    F(io_uring_register, sys_ni_syscall, 0)                                    \
    F(dbgprint, sys_dbgprint, 0)

static long sys_clone(struct registers* regs, unsigned long flags,
                      void* user_stack, pid_t* user_parent_tid, void* user_tls,
                      pid_t* user_child_tid) {
    return clone_user_task(regs, flags, user_stack, user_parent_tid,
                           user_child_tid, user_tls);
}

static struct syscall syscalls[] = {
#define F(name, handler, flags)                                                \
    [SYS_##name] = {                                                           \
        #name,                                                                 \
        (uintptr_t)(handler),                                                  \
        (flags),                                                               \
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

static struct syscall_abi abi = {
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

void syscall_init(void) {
    arch_interrupts_set_handler(SYSCALL_VECTOR, handler);
    idt_set_gate_user_callable(SYSCALL_VECTOR);
    idt_flush();
}
