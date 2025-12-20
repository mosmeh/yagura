#include "../private.h"
#include <sys/mount.h>

int mount(const char* source, const char* target, const char* filesystemtype,
          unsigned long mountflags, const void* data) {
    return __syscall_return(
        SYSCALL5(mount, source, target, filesystemtype, mountflags, data));
}
