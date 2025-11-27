#include "times.h"
#include <private.h>

clock_t times(struct tms* buf) {
    return __syscall_return(SYSCALL1(times, buf));
}
