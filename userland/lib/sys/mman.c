#include "mman.h"
#include <private.h>

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
    RETURN_WITH_ERRNO(void*,
                      SYSCALL6(mmap, addr, length, prot, flags, fd, offset));
}

int munmap(void* addr, size_t length) {
    RETURN_WITH_ERRNO(int, SYSCALL2(munmap, addr, length));
}
