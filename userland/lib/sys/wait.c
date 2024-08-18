#include "wait.h"
#include <private.h>

pid_t waitpid(pid_t pid, int* wstatus, int options) {
    RETURN_WITH_ERRNO(pid_t, SYSCALL3(waitpid, pid, wstatus, options));
}
