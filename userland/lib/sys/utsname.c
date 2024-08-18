#include "utsname.h"
#include <private.h>

int uname(struct utsname* buf) { RETURN_WITH_ERRNO(int, SYSCALL1(uname, buf)); }
