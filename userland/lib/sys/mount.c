#include "mount.h"
#include <private.h>

int mount(const char* source, const char* target, const char* filesystemtype,
          unsigned long mountflags, const void* data) {
    RETURN_WITH_ERRNO(
        int, SYSCALL5(mount, source, target, filesystemtype, mountflags, data));
}
