#include "stat.h"
#include <unistd.h>

int mkfifo(const char* pathname, mode_t mode) {
    return mknod(pathname, mode | S_IFIFO, 0);
}
