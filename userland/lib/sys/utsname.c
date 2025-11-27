#include "utsname.h"
#include <private.h>

int uname(struct utsname* buf) {
    return __syscall_return(SYSCALL1(uname, buf));
}
