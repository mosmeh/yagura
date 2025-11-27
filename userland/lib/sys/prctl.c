#include "prctl.h"
#include <private.h>
#include <stdarg.h>

int prctl(int op, ...) {
    unsigned long x[4];
    va_list ap;
    va_start(ap, op);
    for (int i = 0; i < 4; ++i)
        x[i] = va_arg(ap, unsigned long);
    va_end(ap);
    return __syscall_return(SYSCALL5(prctl, op, x[0], x[1], x[2], x[3]));
}
