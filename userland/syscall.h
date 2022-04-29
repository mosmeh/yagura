#pragma once

#include <kernel/api/sys/socket.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/times.h>
#include <kernel/api/sys/types.h>
#include <kernel/api/time.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

uintptr_t syscall(uint32_t num, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

noreturn void exit(int status);
pid_t fork(void);
pid_t getpid(void);
int setpgid(pid_t pid, pid_t pgid);
pid_t getpgid(pid_t pid);
int sched_yield(void);
int execve(const char* pathname, char* const argv[], char* const envp[]);
pid_t waitpid(pid_t pid, int* wstatus, int options);
clock_t times(struct tms* buf);
int nanosleep(const struct timespec* req, struct timespec* rem);
char* getcwd(char* buf, size_t size);
int chdir(const char* path);

int reboot(int howto);
long sysconf(int name);

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset);
int munmap(void* addr, size_t length);

int dbgputs(const char* str);

int open(const char* pathname, int flags, ...);
int close(int fd);
ssize_t read(int fd, void* buf, size_t count);
ssize_t write(int fd, const void* buf, size_t count);
int ftruncate(int fd, off_t length);
int stat(const char* pathname, struct stat* buf);
int ioctl(int fd, int request, void* argp);
int mkdir(const char* pathname, mode_t mode);
int mknod(const char* pathname, mode_t mode, dev_t dev);
long getdents(int fd, void* dirp, size_t count);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
int pipe(int pipefd[2]);

int socket(int domain, int type, int protocol);
int bind(int sockfd, const sockaddr* addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);

int clock_gettime(clockid_t clk_id, struct timespec* tp);
