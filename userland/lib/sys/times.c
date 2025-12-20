#include "../private.h"
#include <sys/times.h>

clock_t times(struct tms* buf) {
    return __syscall_return(SYSCALL1(times, buf));
}
