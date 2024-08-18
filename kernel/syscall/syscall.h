#pragma once

#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/socket.h>
#include <kernel/api/time.h>
#include <stddef.h>

#define ENUMERATE_SYSCALLS(F)                                                  \
    F(exit)                                                                    \
    F(fork)                                                                    \
    F(read)                                                                    \
    F(write)                                                                   \
    F(open)                                                                    \
    F(close)                                                                   \
    F(waitpid)                                                                 \
    F(link)                                                                    \
    F(unlink)                                                                  \
    F(execve)                                                                  \
    F(chdir)                                                                   \
    F(mknod)                                                                   \
    F(lseek)                                                                   \
    F(getpid)                                                                  \
    F(mount)                                                                   \
    F(kill)                                                                    \
    F(rename)                                                                  \
    F(mkdir)                                                                   \
    F(rmdir)                                                                   \
    F(pipe)                                                                    \
    F(times)                                                                   \
    F(ioctl)                                                                   \
    F(fcntl)                                                                   \
    F(setpgid)                                                                 \
    F(dup2)                                                                    \
    F(symlink)                                                                 \
    F(readlink)                                                                \
    F(reboot)                                                                  \
    F(munmap)                                                                  \
    F(ftruncate)                                                               \
    F(stat)                                                                    \
    F(lstat)                                                                   \
    F(uname)                                                                   \
    F(clone)                                                                   \
    F(getpgid)                                                                 \
    F(getdents)                                                                \
    F(sched_yield)                                                             \
    F(poll)                                                                    \
    F(getcwd)                                                                  \
    F(mmap)                                                                    \
    F(gettid)                                                                  \
    F(exit_group)                                                              \
    F(clock_gettime)                                                           \
    F(clock_nanosleep)                                                         \
    F(socket)                                                                  \
    F(bind)                                                                    \
    F(connect)                                                                 \
    F(listen)                                                                  \
    F(accept4)                                                                 \
    F(shutdown)                                                                \
    F(sysconf)                                                                 \
    F(dbgprint)

struct registers;
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
int sys_symlink(const char* target, const char* linkpath);
ssize_t sys_readlink(const char* pathname, char* buf, size_t bufsiz);
int sys_reboot(int magic, int magic2, int op, void* arg);
int sys_munmap(void* addr, size_t length);
int sys_ftruncate(int fd, off_t length);
int sys_stat(const char* pathname, struct linux_stat* buf);
int sys_lstat(const char* pathname, struct linux_stat* buf);
int sys_uname(struct utsname* buf);
int sys_clone(struct registers*, unsigned long flags, void* stack);
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
long sys_sysconf(int name);
int sys_dbgprint(const char* str);
