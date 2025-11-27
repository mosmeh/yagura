#include "errno.h"
#include <err.h>

_Thread_local int errno;

uintptr_t __syscall_return(uintptr_t rc) {
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    return rc;
}
