#include "sysinfo.h"
#include <private.h>

int sysinfo(struct sysinfo* info) {
    RETURN_WITH_ERRNO(int, SYSCALL1(sysinfo, info));
}
