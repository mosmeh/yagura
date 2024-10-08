#pragma once

#include <kernel/api/sys/mman.h>
#include <stddef.h>
#include <sys/types.h>

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset);
int munmap(void* addr, size_t length);
