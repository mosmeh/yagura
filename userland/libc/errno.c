#include <err.h>
#include <errno.h>

_Thread_local int errno;

unsigned long __syscall_return(unsigned long rc) {
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    return rc;
}
