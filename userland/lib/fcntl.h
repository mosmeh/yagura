#pragma once

#include <kernel/api/fcntl.h>

int open(const char* pathname, int flags, ...);
int fcntl(int fd, int cmd, ...);
