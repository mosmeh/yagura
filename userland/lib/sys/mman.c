#include "mman.h"
#include <private.h>

#define MMAP2_PAGE_UNIT 4096

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
    if (offset % MMAP2_PAGE_UNIT) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    RETURN_WITH_ERRNO(void*, SYSCALL6(mmap2, addr, length, prot, flags, fd,
                                      offset / MMAP2_PAGE_UNIT));
}

int munmap(void* addr, size_t length) {
    RETURN_WITH_ERRNO(int, SYSCALL2(munmap, addr, length));
}
