#include "../private.h"
#include <errno.h>
#include <sys/mman.h>

#define MMAP2_PAGE_UNIT 4096

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
    if (offset % MMAP2_PAGE_UNIT) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    return (void*)__syscall_return(SYSCALL6(mmap2, addr, length, prot, flags,
                                            fd, offset / MMAP2_PAGE_UNIT));
}

int munmap(void* addr, size_t length) {
    return __syscall_return(SYSCALL2(munmap, addr, length));
}

int mprotect(void* addr, size_t len, int prot) {
    return __syscall_return(SYSCALL3(mprotect, addr, len, prot));
}

int msync(void* addr, size_t length, int flags) {
    return __syscall_return(SYSCALL3(msync, addr, length, flags));
}
