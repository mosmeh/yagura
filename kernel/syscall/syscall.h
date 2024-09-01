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
    F(exit, 0)                                                                 \
    F(fork, SYSCALL_RAW_REGISTERS)                                             \
    F(read, 0)                                                                 \
    F(write, 0)                                                                \
    F(open, 0)                                                                 \
    F(close, 0)                                                                \
    F(waitpid, 0)                                                              \
    F(link, 0)                                                                 \
    F(unlink, 0)                                                               \
    F(execve, 0)                                                               \
    F(chdir, 0)                                                                \
    F(mknod, 0)                                                                \
    F(lseek, 0)                                                                \
    F(getpid, 0)                                                               \
    F(mount, 0)                                                                \
    F(kill, 0)                                                                 \
    F(rename, 0)                                                               \
    F(mkdir, 0)                                                                \
    F(rmdir, 0)                                                                \
    F(pipe, 0)                                                                 \
    F(times, 0)                                                                \
    F(ioctl, 0)                                                                \
    F(fcntl, 0)                                                                \
    F(setpgid, 0)                                                              \
    F(dup2, 0)                                                                 \
    F(sigaction, 0)                                                            \
    F(sigsuspend, 0)                                                           \
    F(sigpending, 0)                                                           \
    F(symlink, 0)                                                              \
    F(readlink, 0)                                                             \
    F(reboot, 0)                                                               \
    F(munmap, 0)                                                               \
    F(ftruncate, 0)                                                            \
    F(stat, 0)                                                                 \
    F(lstat, 0)                                                                \
    F(uname, 0)                                                                \
    F(sigreturn, SYSCALL_RAW_REGISTERS | SYSCALL_NO_ERROR)                     \
    F(clone, SYSCALL_RAW_REGISTERS)                                            \
    F(sigprocmask, 0)                                                          \
    F(getpgid, 0)                                                              \
    F(getdents, 0)                                                             \
    F(sched_yield, 0)                                                          \
    F(poll, 0)                                                                 \
    F(getcwd, 0)                                                               \
    F(mmap, 0)                                                                 \
    F(gettid, 0)                                                               \
    F(exit_group, 0)                                                           \
    F(clock_gettime, 0)                                                        \
    F(clock_nanosleep, 0)                                                      \
    F(socket, 0)                                                               \
    F(bind, 0)                                                                 \
    F(connect, 0)                                                              \
    F(listen, 0)                                                               \
    F(accept4, 0)                                                              \
    F(shutdown, 0)                                                             \
    F(dbgprint, 0)

struct registers;
struct sigaction;
struct tms;
struct utsname;
struct linux_dirent;
struct linux_stat;

void sys_exit(int status);
pid_t sys_fork(struct registers*);
ssize_t sys_read(int fd, void* buf, size_t count);
ssize_t sys_write(int fd, const void* buf, size_t count);
int sys_open(const char* pathname, int flags, unsigned mode);
int sys_close(int fd);
pid_t sys_waitpid(pid_t pid, int* wstatus, int options);
int sys_link(const char* oldpath, const char* newpath);
int sys_unlink(const char* pathname);
int sys_execve(const char* pathname, char* const argv[], char* const envp[]);
int sys_chdir(const char* path);
int sys_mknod(const char* pathname, mode_t mode, dev_t dev);
off_t sys_lseek(int fd, off_t offset, int whence);
pid_t sys_getpid(void);
int sys_mount(const char* source, const char* target,
              const char* filesystemtype, unsigned long mountflags,
              const void* data);
int sys_kill(pid_t pid, int sig);
int sys_rename(const char* oldpath, const char* newpath);
int sys_mkdir(const char* pathname, mode_t mode);
int sys_rmdir(const char* pathname);
int sys_pipe(int pipefd[2]);
clock_t sys_times(struct tms* buf);
int sys_ioctl(int fd, int request, void* argp);
int sys_fcntl(int fd, int cmd, uintptr_t arg);
int sys_setpgid(pid_t pid, pid_t pgid);
int sys_dup2(int oldfd, int newfd);
int sys_sigaction(int signum, const struct sigaction* act,
                  struct sigaction* oldact);
int sys_sigsuspend(const sigset_t* mask);
int sys_sigpending(sigset_t* set);
int sys_symlink(const char* target, const char* linkpath);
ssize_t sys_readlink(const char* pathname, char* buf, size_t bufsiz);
int sys_reboot(int magic, int magic2, int op, void* arg);
int sys_munmap(void* addr, size_t length);
int sys_ftruncate(int fd, off_t length);
int sys_stat(const char* pathname, struct linux_stat* buf);
int sys_lstat(const char* pathname, struct linux_stat* buf);
int sys_uname(struct utsname* buf);
int sys_sigreturn(struct registers*);
int sys_clone(struct registers*, unsigned long flags, void* stack);
int sys_sigprocmask(int how, const sigset_t* set, sigset_t* oldset);
pid_t sys_getpgid(pid_t pid);
long sys_getdents(int fd, struct linux_dirent* dirp, size_t count);
int sys_sched_yield(void);
int sys_poll(struct pollfd* fds, nfds_t nfds, int timeout);
int sys_getcwd(char* buf, size_t size);
void* sys_mmap(void* addr, size_t length, int prot, int flags, int fd,
               off_t offset);
pid_t sys_gettid(void);
void sys_exit_group(int status);
int sys_clock_gettime(clockid_t clk_id, struct timespec* tp);
int sys_clock_nanosleep(clockid_t clockid, int flags,
                        const struct timespec* request,
                        struct timespec* remain);
int sys_socket(int domain, int type, int protocol);
int sys_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int sys_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int sys_listen(int sockfd, int backlog);
int sys_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen,
                int flags);
int sys_shutdown(int sockfd, int how);
int sys_dbgprint(const char* str);
