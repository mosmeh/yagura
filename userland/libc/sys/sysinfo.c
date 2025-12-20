#include "../private.h"
#include <sys/sysinfo.h>

int sysinfo(struct sysinfo* info) {
    return __syscall_return(SYSCALL1(sysinfo, info));
}
