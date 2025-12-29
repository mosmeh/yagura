#include "private.h"
#include <sys/random.h>

ssize_t getrandom(void* buf, size_t buflen, unsigned int flags) {
    return __syscall_return(SYSCALL3(getrandom, buf, buflen, flags));
}
