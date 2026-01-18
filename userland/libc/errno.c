#include <err.h>
#include <errno.h>

static _Thread_local int errno_value;

int* __errno_location(void) { return &errno_value; }

unsigned long __syscall_return(unsigned long rc) {
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    return rc;
}
