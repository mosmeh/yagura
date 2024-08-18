#include "times.h"
#include <private.h>

clock_t times(struct tms* buf) {
    RETURN_WITH_ERRNO(clock_t, SYSCALL1(times, buf));
}
