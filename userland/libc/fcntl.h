#pragma once

#include <kernel/api/fcntl.h>
#include <sys/types.h>

int open(const char* pathname, int flags, ...);
int openat(int dirfd, const char* pathname, int flags, mode_t mode);
int creat(const char* pathname, mode_t mode);
int fcntl(int fd, int cmd, ...);
int fcntl64(int fd, int cmd, ...);
