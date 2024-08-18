#include "signal.h"
#include <private.h>

int kill(pid_t pid, int sig) {
    RETURN_WITH_ERRNO(int, SYSCALL2(kill, pid, sig));
}
