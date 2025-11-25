#pragma once

#include <kernel/api/signal.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/socket.h>
#include <kernel/api/time.h>
#include <stddef.h>

// ERESTARTSYS is used to indicate that a syscall was interrupted by a signal
// and should be restarted if the sigaction has the SA_RESTART flag set.
#define ERESTARTSYS 512

// Takes struct registers* as first argument.
#define SYSCALL_RAW_REGISTERS 0x1

// The return value should not be checked for error.
// The value should be stored in eax without post-processing.
#define SYSCALL_NO_ERROR 0x2

#define ENUMERATE_SYSCALLS(F)                                                  \
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
    F(oldstat, sys_stat, 0)                                                    \
    F(lseek, sys_lseek, 0)                                                     \
    F(getpid, sys_getpid, 0)                                                   \
    F(mount, sys_mount, 0)                                                     \
    F(getuid, sys_getuid16, 0)                                                 \
    F(stime, sys_stime32, 0)                                                   \
    F(oldfstat, sys_fstat, 0)                                                  \
    F(pause, sys_pause, 0)                                                     \
    F(access, sys_access, 0)                                                   \
    F(sync, sys_sync, 0)                                                       \
    F(kill, sys_kill, 0)                                                       \
    F(rename, sys_rename, 0)                                                   \
    F(mkdir, sys_mkdir, 0)                                                     \
    F(rmdir, sys_rmdir, 0)                                                     \
    F(dup, sys_dup, 0)                                                         \
    F(pipe, sys_pipe, 0)                                                       \
    F(times, sys_times, 0)                                                     \
    F(getgid, sys_getgid16, 0)                                                 \
    F(geteuid, sys_geteuid16, 0)                                               \
    F(getegid, sys_getegid16, 0)                                               \
    F(ioctl, sys_ioctl, 0)                                                     \
    F(fcntl, sys_fcntl, 0)                                                     \
    F(setpgid, sys_setpgid, 0)                                                 \
    F(oldolduname, sys_olduname, 0)                                            \
    F(dup2, sys_dup2, 0)                                                       \
    F(getppid, sys_getppid, 0)                                                 \
    F(getpgrp, sys_getpgrp, 0)                                                 \
    F(sigaction, sys_sigaction, 0)                                             \
    F(sigsuspend, sys_sigsuspend, 0)                                           \
    F(sigpending, sys_sigpending, 0)                                           \
    F(sethostname, sys_sethostname, 0)                                         \
    F(gettimeofday, sys_gettimeofday, 0)                                       \
    F(settimeofday, sys_settimeofday, 0)                                       \
    F(select, sys_old_select, 0)                                               \
    F(symlink, sys_symlink, 0)                                                 \
    F(oldlstat, sys_lstat, 0)                                                  \
    F(readlink, sys_readlink, 0)                                               \
    F(reboot, sys_reboot, 0)                                                   \
    F(readdir, sys_readdir, 0)                                                 \
    F(mmap, sys_old_mmap, 0)                                                   \
    F(munmap, sys_munmap, 0)                                                   \
    F(truncate, sys_truncate, 0)                                               \
    F(ftruncate, sys_ftruncate, 0)                                             \
    F(stat, sys_newstat, 0)                                                    \
    F(lstat, sys_newlstat, 0)                                                  \
    F(fstat, sys_newfstat, 0)                                                  \
    F(olduname, sys_uname, 0)                                                  \
    F(wait4, sys_wait4, 0)                                                     \
    F(sysinfo, sys_sysinfo, 0)                                                 \
    F(fsync, sys_fsync, 0)                                                     \
    F(sigreturn, sys_sigreturn, SYSCALL_RAW_REGISTERS | SYSCALL_NO_ERROR)      \
    F(clone, sys_clone, SYSCALL_RAW_REGISTERS)                                 \
    F(setdomainname, sys_setdomainname, 0)                                     \
    F(uname, sys_newuname, 0)                                                  \
    F(mprotect, sys_mprotect, 0)                                               \
    F(sigprocmask, sys_sigprocmask, 0)                                         \
    F(getpgid, sys_getpgid, 0)                                                 \
    F(_llseek, sys_llseek, 0)                                                  \
    F(getdents, sys_getdents, 0)                                               \
    F(_newselect, sys_select, 0)                                               \
    F(msync, sys_msync, 0)                                                     \
    F(readv, sys_readv, 0)                                                     \
    F(writev, sys_writev, 0)                                                   \
    F(fdatasync, sys_fdatasync, 0)                                             \
    F(sched_yield, sys_sched_yield, 0)                                         \
    F(nanosleep, sys_nanosleep_time32, 0)                                      \
    F(poll, sys_poll, 0)                                                       \
    F(prctl, sys_prctl, 0)                                                     \
    F(pread64, sys_ia32_pread64, 0)                                            \
    F(pwrite64, sys_ia32_pwrite64, 0)                                          \
    F(getcwd, sys_getcwd, 0)                                                   \
    F(mmap2, sys_mmap_pgoff, 0)                                                \
    F(truncate64, sys_ia32_truncate64, 0)                                      \
    F(ftruncate64, sys_ia32_ftruncate64, 0)                                    \
    F(stat64, sys_stat64, 0)                                                   \
    F(lstat64, sys_lstat64, 0)                                                 \
    F(fstat64, sys_fstat64, 0)                                                 \
    F(getuid32, sys_getuid, 0)                                                 \
    F(getgid32, sys_getgid, 0)                                                 \
    F(geteuid32, sys_geteuid, 0)                                               \
    F(getegid32, sys_getegid, 0)                                               \
    F(getdents64, sys_getdents64, 0)                                           \
    F(fcntl64, sys_fcntl64, 0)                                                 \
    F(gettid, sys_gettid, 0)                                                   \
    F(set_thread_area, sys_set_thread_area, 0)                                 \
    F(get_thread_area, sys_get_thread_area, 0)                                 \
    F(exit_group, sys_exit_group, 0)                                           \
    F(clock_settime, sys_clock_settime32, 0)                                   \
    F(clock_gettime, sys_clock_gettime32, 0)                                   \
    F(clock_getres, sys_clock_getres_time32, 0)                                \
    F(clock_nanosleep, sys_clock_nanosleep_time32, 0)                          \
    F(getcpu, sys_getcpu, 0)                                                   \
    F(dup3, sys_dup3, 0)                                                       \
    F(pipe2, sys_pipe2, 0)                                                     \
    F(syncfs, sys_syncfs, 0)                                                   \
    F(socket, sys_socket, 0)                                                   \
    F(bind, sys_bind, 0)                                                       \
    F(connect, sys_connect, 0)                                                 \
    F(listen, sys_listen, 0)                                                   \
    F(accept4, sys_accept4, 0)                                                 \
    F(shutdown, sys_shutdown, 0)                                               \
    F(clock_gettime64, sys_clock_gettime, 0)                                   \
    F(clock_settime64, sys_clock_settime, 0)                                   \
    F(clock_getres_time64, sys_clock_getres, 0)                                \
    F(clock_nanosleep_time64, sys_clock_nanosleep, 0)                          \
    F(dbgprint, sys_dbgprint, 0)

struct registers;
struct getcpu_cache;
struct iovec;
struct mmap_arg_struct;
struct rusage;
struct sel_arg_struct;
struct sigaction;
struct sysinfo;
struct timezone;
struct tms;
struct user_desc;
struct utsname;
struct linux_dirent;
struct linux_old_dirent;
struct linux_old_stat;
struct linux_old_utsname;
struct linux_oldold_utsname;
struct linux_stat;
struct linux_stat64;
struct linux_timeval;

void sys_exit(int status);
pid_t sys_fork(struct registers*);
ssize_t sys_read(int fd, void* buf, size_t count);
ssize_t sys_write(int fd, const void* buf, size_t count);
int sys_open(const char* pathname, int flags, unsigned mode);
int sys_close(int fd);
pid_t sys_waitpid(pid_t pid, int* wstatus, int options);
int sys_creat(const char* pathname, mode_t mode);
int sys_link(const char* oldpath, const char* newpath);
int sys_unlink(const char* pathname);
int sys_execve(const char* pathname, char* const argv[], char* const envp[]);
int sys_chdir(const char* path);
time32_t sys_time32(time32_t* tloc);
int sys_mknod(const char* pathname, mode_t mode, dev_t dev);
int sys_stat(const char* pathname, struct linux_old_stat* buf);
off_t sys_lseek(int fd, off_t offset, int whence);
pid_t sys_getpid(void);
int sys_mount(const char* source, const char* target,
              const char* filesystemtype, unsigned long mountflags,
              const void* data);
uid_t sys_getuid16(void);
int sys_stime32(const time32_t* t);
int sys_fstat(int fd, struct linux_old_stat* buf);
int sys_pause(void);
int sys_access(const char* pathname, int mode);
int sys_sync(void);
int sys_kill(pid_t pid, int sig);
int sys_rename(const char* oldpath, const char* newpath);
int sys_mkdir(const char* pathname, mode_t mode);
int sys_rmdir(const char* pathname);
int sys_dup(int oldfd);
int sys_pipe(int pipefd[2]);
clock_t sys_times(struct tms* buf);
gid_t sys_getgid16(void);
uid_t sys_geteuid16(void);
gid_t sys_getegid16(void);
int sys_ioctl(int fd, int request, void* argp);
int sys_fcntl(int fd, int cmd, unsigned long arg);
int sys_setpgid(pid_t pid, pid_t pgid);
int sys_olduname(struct linux_oldold_utsname* buf);
int sys_dup2(int oldfd, int newfd);
pid_t sys_getppid(void);
pid_t sys_getpgrp(void);
int sys_sigaction(int signum, const struct sigaction* act,
                  struct sigaction* oldact);
int sys_sigsuspend(const sigset_t* mask);
int sys_sigpending(sigset_t* set);
int sys_sethostname(const char* name, int len);
int sys_gettimeofday(struct linux_timeval* tv, struct timezone* tz);
int sys_settimeofday(const struct linux_timeval* tv, const struct timezone* tz);
int sys_old_select(struct sel_arg_struct*);
int sys_symlink(const char* target, const char* linkpath);
int sys_lstat(const char* pathname, struct linux_old_stat* buf);
ssize_t sys_readlink(const char* pathname, char* buf, size_t bufsiz);
int sys_reboot(int magic, int magic2, int op, void* arg);
ssize_t sys_readdir(int fd, struct linux_old_dirent* dirp, size_t count);
void* sys_old_mmap(struct mmap_arg_struct*);
int sys_munmap(void* addr, size_t length);
int sys_truncate(const char* path, off_t length);
int sys_ftruncate(int fd, off_t length);
int sys_newstat(const char* pathname, struct linux_stat* buf);
int sys_newlstat(const char* pathname, struct linux_stat* buf);
int sys_newfstat(int fd, struct linux_stat* buf);
int sys_uname(struct linux_old_utsname* buf);
pid_t sys_wait4(pid_t pid, int* wstatus, int options, struct rusage* rusage);
int sys_sysinfo(struct sysinfo* info);
int sys_fsync(int fd);
int sys_sigreturn(struct registers*);
int sys_clone(struct registers*, unsigned long flags, void* stack,
              pid_t* parent_tid, pid_t* child_tid, void* tls);
int sys_setdomainname(const char* name, int len);
int sys_newuname(struct utsname* buf);
int sys_mprotect(void* addr, size_t len, int prot);
int sys_sigprocmask(int how, const sigset_t* set, sigset_t* oldset);
pid_t sys_getpgid(pid_t pid);
int sys_llseek(unsigned int fd, unsigned long offset_high,
               unsigned long offset_low, loff_t* result, unsigned int whence);
ssize_t sys_getdents(int fd, struct linux_dirent* dirp, size_t count);
int sys_select(int nfds, unsigned long* readfds, unsigned long* writefds,
               unsigned long* exceptfds, struct linux_timeval* timeout);
int sys_msync(void* addr, size_t length, int flags);
ssize_t sys_readv(int fd, const struct iovec* iov, int iovcnt);
ssize_t sys_writev(int fd, const struct iovec* iov, int iovcnt);
int sys_fdatasync(int fd);
int sys_sched_yield(void);
int sys_nanosleep_time32(const struct timespec32* duration,
                         struct timespec32* rem);
int sys_poll(struct pollfd* fds, nfds_t nfds, int timeout);
int sys_prctl(int op, unsigned long arg2, unsigned long arg3,
              unsigned long arg4, unsigned long arg5);
ssize_t sys_ia32_pread64(int fd, void* buf, size_t count, uint32_t pos_lo,
                         uint32_t pos_hi);
ssize_t sys_ia32_pwrite64(int fd, const void* buf, size_t count,
                          uint32_t pos_lo, uint32_t pos_hi);
int sys_getcwd(char* buf, size_t size);
void* sys_mmap_pgoff(void* addr, size_t length, int prot, int flags, int fd,
                     unsigned long pgoff);
int sys_ia32_truncate64(const char* path, unsigned long offset_low,
                        unsigned long offset_high);
int sys_ia32_ftruncate64(int fd, unsigned long offset_low,
                         unsigned long offset_high);
int sys_stat64(const char* pathname, struct linux_stat64* buf);
int sys_lstat64(const char* pathname, struct linux_stat64* buf);
int sys_fstat64(int fd, struct linux_stat64* buf);
uid_t sys_getuid(void);
gid_t sys_getgid(void);
uid_t sys_geteuid(void);
gid_t sys_getegid(void);
ssize_t sys_getdents64(int fd, struct linux_dirent* dirp, size_t count);
int sys_fcntl64(int fd, int cmd, unsigned long arg);
pid_t sys_gettid(void);
int sys_get_thread_area(struct user_desc* u_info);
int sys_set_thread_area(struct user_desc* u_info);
void sys_exit_group(int status);
int sys_clock_settime32(clockid_t clockid, const struct timespec32* tp);
int sys_clock_gettime32(clockid_t clockid, struct timespec32* tp);
int sys_clock_getres_time32(clockid_t clockid, struct timespec32* res);
int sys_clock_nanosleep_time32(clockid_t clockid, int flags,
                               const struct timespec32* request,
                               struct timespec32* remain);
int sys_getcpu(unsigned int* cpu, unsigned int* node,
               struct getcpu_cache* tcache);
int sys_dup3(int oldfd, int newfd, int flags);
int sys_pipe2(int pipefd[2], int flags);
int sys_syncfs(int fd);
int sys_socket(int domain, int type, int protocol);
int sys_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int sys_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int sys_listen(int sockfd, int backlog);
int sys_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen,
                int flags);
int sys_shutdown(int sockfd, int how);
int sys_clock_gettime(clockid_t clockid, struct timespec* tp);
int sys_clock_settime(clockid_t clockid, const struct timespec* tp);
int sys_clock_getres(clockid_t clockid, struct timespec* res);
int sys_clock_nanosleep(clockid_t clockid, int flags,
                        const struct timespec* request,
                        struct timespec* remain);
int sys_dbgprint(const char* str);
