#include "wait.h"
#include <private.h>

pid_t waitpid(pid_t pid, int* wstatus, int options) {
    RETURN_WITH_ERRNO(pid_t, SYSCALL3(waitpid, pid, wstatus, options));
}

pid_t wait4(pid_t pid, int* wstatus, int options, struct rusage* rusage) {
    RETURN_WITH_ERRNO(pid_t, SYSCALL4(wait4, pid, wstatus, options, rusage));
}
