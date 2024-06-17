#pragma once

#include <kernel/api/sys/stat.h>

int stat(const char* pathname, struct stat* buf);
int mkdir(const char* pathname, mode_t mode);
int mkfifo(const char* pathname, mode_t mode);
