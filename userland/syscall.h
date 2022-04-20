#pragma once

#include <kernel/api/socket.h>
#include <kernel/api/time.h>
#include <kernel/api/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

uintptr_t syscall(uint32_t num, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

noreturn void exit(int status);
pid_t fork(void);
pid_t getpid(void);
int sched_yield(void);
int execve(const char* pathname, char* const argv[], char* const envp[]);
pid_t waitpid(pid_t pid, int* wstatus, int options);
int nanosleep(const struct timespec* req, struct timespec* rem);
char* getcwd(char* buf, size_t size);
int chdir(const char* path);

noreturn void halt(void);

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset);

int dbgputs(const char* str);

int open(const char* pathname, int flags, ...);
int close(int fd);
ssize_t read(int fd, void* buf, size_t count);
ssize_t write(int fd, const void* buf, size_t count);
int ftruncate(int fd, off_t length);
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
