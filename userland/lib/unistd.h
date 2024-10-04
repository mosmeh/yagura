#pragma once

#include <kernel/api/unistd.h>
#include <stddef.h>
#include <sys/types.h>

extern char** environ;

pid_t getpid(void);
pid_t getppid(void);
pid_t gettid(void);
int setpgid(pid_t pid, pid_t pgid);
pid_t getpgid(pid_t pid);
pid_t getpgrp(void);

pid_t fork(void);
int execve(const char* pathname, char* const argv[], char* const envp[]);
int execvpe(const char* file, char* const argv[], char* const envp[]);

uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);

int access(const char* pathname, int mode);
int close(int fd);
ssize_t read(int fd, void* buf, size_t count);
ssize_t write(int fd, const void* buf, size_t count);
ssize_t pread(int fd, void* buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset);
int truncate(const char* path, off_t length);
int ftruncate(int fd, off_t length);
off_t lseek(int fd, off_t offset, int whence);
int mknod(const char* pathname, mode_t mode, dev_t dev);
int link(const char* oldpath, const char* newpath);
int symlink(const char* target, const char* linkpath);
int unlink(const char* pathname);
ssize_t readlink(const char* pathname, char* buf, size_t bufsiz);
int rename(const char* oldpath, const char* newpath);
int rmdir(const char* pathname);

int dup(int oldfd);
int dup2(int oldfd, int newfd);
int dup3(int oldfd, int newfd, int flags);
int pipe(int pipefd[2]);
int pipe2(int pipefd[2], int flags);

char* getcwd(char* buf, size_t size);
int chdir(const char* path);

pid_t tcgetpgrp(int fd);
int tcsetpgrp(int fd, pid_t pgrp);

unsigned int sleep(unsigned int seconds);
int usleep(useconds_t usec);

int pause(void);

int gethostname(char* name, size_t len);
int sethostname(const char* name, size_t len);
int getdomainname(char* name, size_t len);
int setdomainname(const char* name, size_t len);

int reboot(int howto);

enum {
    _SC_ARG_MAX,
    _SC_CLK_TCK,
    _SC_MONOTONIC_CLOCK,
    _SC_OPEN_MAX,
    _SC_PAGESIZE,
    _SC_PAGE_SIZE = _SC_PAGESIZE,
    _SC_SYMLOOP_MAX,
};

long sysconf(int name);
