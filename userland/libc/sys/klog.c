#include "../private.h"
#include <sys/klog.h>

int klogctl(int type, char* bufp, int len) {
    return __syscall_return(SYSCALL3(syslog, type, bufp, len));
}
