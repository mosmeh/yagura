#pragma once

#include <common/stddef.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/socket.h>
#include <kernel/api/time.h>

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
struct utsname;
struct linux_dirent;
struct linux_old_dirent;
struct linux_old_stat;
struct linux_old_utsname;
struct linux_oldold_utsname;
struct linux_stat;
struct linux_stat64;
struct linux_timeval;

// ERESTARTSYS is used to indicate that a syscall was interrupted by a signal
// and should be restarted if the sigaction has the SA_RESTART flag set.
#define ERESTARTSYS 512

// Takes struct registers* as first argument.
#define SYSCALL_RAW_REGISTERS 0x1

// The return value should not be checked for error.
// The value should be stored in eax without post-processing.
#define SYSCALL_NO_ERROR 0x2

struct syscall {
    const char* name;
    uintptr_t handler;
    unsigned flags; // SYSCALL_*
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

// Unimplemented syscall handler
long sys_ni_syscall(void);

long sys_exit(int status);
long sys_fork(struct registers*);
long sys_read(int fd, void* buf, size_t count);
long sys_write(int fd, const void* buf, size_t count);
long sys_open(const char* pathname, int flags, unsigned mode);
long sys_close(int fd);
long sys_waitpid(pid_t pid, int* wstatus, int options);
long sys_creat(const char* pathname, mode_t mode);
long sys_link(const char* oldpath, const char* newpath);
long sys_unlink(const char* pathname);
long sys_execve(const char* pathname, char* const argv[], char* const envp[]);
long sys_chdir(const char* path);
long sys_time32(time32_t* tloc);
long sys_mknod(const char* pathname, mode_t mode, dev_t dev);
long sys_chmod(const char* pathname, mode_t mode);
long sys_lchown16(const char* pathname, linux_old_uid_t owner,
                  linux_old_gid_t group);
long sys_stat(const char* pathname, struct linux_old_stat* buf);
long sys_lseek(int fd, off_t offset, int whence);
long sys_getpid(void);
long sys_mount(const char* source, const char* target,
               const char* filesystemtype, unsigned long mountflags,
               const void* data);
long sys_getuid16(void);
long sys_stime32(const time32_t* t);
long sys_fstat(int fd, struct linux_old_stat* buf);
long sys_pause(void);
long sys_access(const char* pathname, int mode);
long sys_sync(void);
long sys_kill(pid_t pid, int sig);
long sys_rename(const char* oldpath, const char* newpath);
long sys_mkdir(const char* pathname, mode_t mode);
long sys_rmdir(const char* pathname);
long sys_dup(int oldfd);
long sys_pipe(int pipefd[2]);
long sys_times(struct tms* buf);
long sys_getgid16(void);
long sys_signal(int signum, sighandler_t handler);
long sys_geteuid16(void);
long sys_getegid16(void);
long sys_ioctl(int fd, unsigned cmd, unsigned long arg);
long sys_fcntl(int fd, int cmd, unsigned long arg);
long sys_setpgid(pid_t pid, pid_t pgid);
long sys_olduname(struct linux_oldold_utsname* buf);
long sys_chroot(const char* path);
long sys_dup2(int oldfd, int newfd);
long sys_getppid(void);
long sys_getpgrp(void);
long sys_sigaction(int signum, const struct sigaction* act,
                   struct sigaction* oldact);
long sys_sgetmask(void);
long sys_ssetmask(long newmask);
long sys_sigsuspend(const sigset_t* mask);
long sys_sigpending(sigset_t* set);
long sys_sethostname(const char* name, int len);
long sys_gettimeofday(struct linux_timeval* tv, struct timezone* tz);
long sys_settimeofday(const struct linux_timeval* tv,
                      const struct timezone* tz);
long sys_getgroups16(int size, linux_old_gid_t* list);
long sys_old_select(struct sel_arg_struct*);
long sys_symlink(const char* target, const char* linkpath);
long sys_lstat(const char* pathname, struct linux_old_stat* buf);
long sys_readlink(const char* pathname, char* buf, size_t bufsiz);
long sys_reboot(int magic, int magic2, int op, void* arg);
long sys_old_readdir(int fd, struct linux_old_dirent* dirp, size_t count);
long sys_old_mmap(struct mmap_arg_struct*);
long sys_munmap(void* addr, size_t length);
long sys_truncate(const char* path, off_t length);
long sys_ftruncate(int fd, off_t length);
long sys_fchmod(int fd, mode_t mode);
long sys_fchown16(int fd, linux_old_uid_t owner, linux_old_gid_t group);
long sys_newstat(const char* pathname, struct linux_stat* buf);
long sys_newlstat(const char* pathname, struct linux_stat* buf);
long sys_newfstat(int fd, struct linux_stat* buf);
long sys_uname(struct linux_old_utsname* buf);
long sys_wait4(pid_t pid, int* wstatus, int options, struct rusage* rusage);
long sys_sysinfo(struct sysinfo* info);
long sys_fsync(int fd);
long sys_sigreturn(struct registers*);
long sys_clone(struct registers*, unsigned long flags, void* stack,
               pid_t* parent_tid, pid_t* child_tid, void* tls);
long sys_setdomainname(const char* name, int len);
long sys_newuname(struct utsname* buf);
long sys_mprotect(void* addr, size_t len, int prot);
long sys_sigprocmask(int how, const sigset_t* set, sigset_t* oldset);
long sys_getpgid(pid_t pid);
long sys_fchdir(int fd);
long sys_llseek(unsigned int fd, unsigned long offset_high,
                unsigned long offset_low, loff_t* result, unsigned int whence);
long sys_getdents(int fd, struct linux_dirent* dirp, size_t count);
long sys_select(int nfds, unsigned long* readfds, unsigned long* writefds,
                unsigned long* exceptfds, struct linux_timeval* timeout);
long sys_msync(void* addr, size_t length, int flags);
long sys_readv(int fd, const struct iovec* iov, int iovcnt);
long sys_writev(int fd, const struct iovec* iov, int iovcnt);
long sys_getsid(pid_t pid);
long sys_fdatasync(int fd);
long sys_sched_yield(void);
long sys_nanosleep_time32(const struct timespec32* duration,
                          struct timespec32* rem);
long sys_getresuid16(linux_old_uid_t* ruid, linux_old_uid_t* euid,
                     linux_old_uid_t* suid);
long sys_poll(struct pollfd* fds, nfds_t nfds, int timeout);
long sys_getresgid16(linux_old_gid_t* rgid, linux_old_gid_t* egid,
                     linux_old_gid_t* sgid);
long sys_prctl(int op, unsigned long arg2, unsigned long arg3,
               unsigned long arg4, unsigned long arg5);
long sys_chown16(const char* pathname, linux_old_uid_t owner,
                 linux_old_gid_t group);
long sys_getcwd(char* buf, size_t size);
long sys_vfork(struct registers*);
long sys_mmap_pgoff(void* addr, size_t length, int prot, int flags, int fd,
                    unsigned long pgoff);
long sys_stat64(const char* pathname, struct linux_stat64* buf);
long sys_lstat64(const char* pathname, struct linux_stat64* buf);
long sys_fstat64(int fd, struct linux_stat64* buf);
long sys_lchown(const char* pathname, uid_t owner, gid_t group);
long sys_getuid(void);
long sys_getgid(void);
long sys_geteuid(void);
long sys_getegid(void);
long sys_getgroups(int size, gid_t* list);
long sys_fchown(int fd, uid_t owner, gid_t group);
long sys_getresuid(uid_t* ruid, uid_t* euid, uid_t* suid);
long sys_getresgid(gid_t* rgid, gid_t* egid, gid_t* sgid);
long sys_chown(const char* pathname, uid_t owner, gid_t group);
long sys_getdents64(int fd, struct linux_dirent* dirp, size_t count);
long sys_fcntl64(int fd, int cmd, unsigned long arg);
long sys_gettid(void);
long sys_tkill(pid_t tid, int sig);
long sys_exit_group(int status);
long sys_clock_settime32(clockid_t clockid, const struct timespec32* tp);
long sys_clock_gettime32(clockid_t clockid, struct timespec32* tp);
long sys_clock_getres_time32(clockid_t clockid, struct timespec32* res);
long sys_clock_nanosleep_time32(clockid_t clockid, int flags,
                                const struct timespec32* request,
                                struct timespec32* remain);
long sys_tgkill(pid_t tgid, pid_t tid, int sig);
long sys_openat(int dirfd, const char* pathname, int flags, mode_t mode);
long sys_mkdirat(int dirfd, const char* pathname, mode_t mode);
long sys_mknodat(int dirfd, const char* pathname, mode_t mode, dev_t dev);
long sys_fchownat(int dirfd, const char* pathname, uid_t owner, gid_t group,
                  int flags);
long sys_fstatat64(int dirfd, const char* pathname, struct linux_stat64* buf,
                   int flags);
long sys_unlinkat(int dirfd, const char* pathname, int flags);
long sys_renameat(int olddirfd, const char* oldpath, int newdirfd,
                  const char* newpath);
long sys_linkat(int olddirfd, const char* oldpath, int newdirfd,
                const char* newpath, int flags);
long sys_symlinkat(const char* target, int newdirfd, const char* linkpath);
long sys_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsiz);
long sys_fchmodat(int dirfd, const char* pathname, mode_t mode);
long sys_faccessat(int dirfd, const char* pathname, int mode);
long sys_pselect6_time32(int nfds, unsigned long* readfds,
                         unsigned long* writefds, unsigned long* exceptfds,
                         struct timespec32* timeout, const void* sigmask);
long sys_ppoll_time32(struct pollfd* fds, nfds_t nfds,
                      struct timespec32* timeout, const sigset_t* sigmask,
                      size_t sigsetsize);
long sys_getcpu(unsigned int* cpu, unsigned int* node,
                struct getcpu_cache* tcache);
long sys_dup3(int oldfd, int newfd, int flags);
long sys_pipe2(int pipefd[2], int flags);
long sys_syncfs(int fd);
long sys_renameat2(int olddirfd, const char* oldpath, int newdirfd,
                   const char* newpath, unsigned int flags);
long sys_getrandom(void* buf, size_t buflen, unsigned int flags);
long sys_socket(int domain, int type, int protocol);
long sys_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
long sys_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
long sys_listen(int sockfd, int backlog);
long sys_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen,
                 int flags);
long sys_shutdown(int sockfd, int how);
long sys_clock_gettime(clockid_t clockid, struct timespec* tp);
long sys_clock_settime(clockid_t clockid, const struct timespec* tp);
long sys_clock_getres(clockid_t clockid, struct timespec* res);
long sys_clock_nanosleep(clockid_t clockid, int flags,
                         const struct timespec* request,
                         struct timespec* remain);
long sys_pselect6(int nfds, unsigned long* readfds, unsigned long* writefds,
                  unsigned long* exceptfds, struct timespec* timeout,
                  const void* sigmask);
long sys_ppoll(struct pollfd* fds, nfds_t nfds, struct timespec* timeout,
               const sigset_t* sigmask, size_t sigsetsize);
long sys_dbgprint(const char* str);
