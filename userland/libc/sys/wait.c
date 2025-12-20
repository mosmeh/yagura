#include "../private.h"
#include <sys/wait.h>

pid_t waitpid(pid_t pid, int* wstatus, int options) {
    return __syscall_return(SYSCALL3(waitpid, pid, wstatus, options));
}

pid_t wait4(pid_t pid, int* wstatus, int options, struct rusage* rusage) {
    return __syscall_return(SYSCALL4(wait4, pid, wstatus, options, rusage));
}
