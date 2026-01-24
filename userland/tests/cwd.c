#include <errno.h>
#include <panic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/limits.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char buf[PATH_MAX];

    errno = 0;
    ASSERT(!getcwd(NULL, 0));
    ASSERT(errno == EINVAL);

    errno = 0;
    ASSERT(!getcwd(buf, 0));
    ASSERT(errno == EINVAL);

    errno = 0;
    ASSERT_ERR(syscall(SYS_getcwd, NULL, 0));
    ASSERT(errno == ERANGE);

    errno = 0;
    ASSERT_ERR(syscall(SYS_getcwd, (void*)1, 0));
    ASSERT(errno == ERANGE);

    errno = 0;
    ASSERT_ERR(syscall(SYS_getcwd, buf, 0));
    ASSERT(errno == ERANGE);

    errno = 0;
    ASSERT(!getcwd(NULL, 1));
    ASSERT(errno == ERANGE);

    errno = 0;
    ASSERT(!getcwd((void*)1, 1));
    ASSERT(errno == ERANGE);

    errno = 0;
    ASSERT(!getcwd(buf, 1));
    ASSERT(errno == ERANGE);

    errno = 0;
    ASSERT(!getcwd(NULL, sizeof(buf)));
    ASSERT(errno == EFAULT);

    errno = 0;
    ASSERT(!getcwd((void*)1, sizeof(buf)));
    ASSERT(errno == EFAULT);

    rmdir("/tmp/test-cwd");
    ASSERT_OK(mkdir("/tmp/test-cwd", 0755));
    ASSERT_OK(chdir("/tmp/test-cwd"));

    errno = 0;
    ASSERT(getcwd(buf, sizeof(buf)) == buf);
    ASSERT(errno == 0);
    ASSERT(!strcmp(buf, "/tmp/test-cwd"));

    return EXIT_SUCCESS;
}
