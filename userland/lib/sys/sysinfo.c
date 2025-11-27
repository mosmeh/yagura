#include "sysinfo.h"
#include <private.h>

int sysinfo(struct sysinfo* info) {
    return __syscall_return(SYSCALL1(sysinfo, info));
}
