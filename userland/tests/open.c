#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    unlink("/tmp/test-open/foo");
    rmdir("/tmp/test-open");

    ASSERT_OK(mkdir("/tmp/test-open", 0755));

    ASSERT_ERR(open("/tmp/test-open/foo", 0));
    ASSERT(errno == ENOENT);

    ASSERT_OK(open("/tmp/test-open/foo", O_CREAT | O_EXCL, 0644));
    ASSERT_OK(open("/tmp/test-open/foo", O_CREAT, 0644));

    ASSERT_ERR(open("/tmp/test-open/foo", O_CREAT | O_EXCL, 0644));
    ASSERT(errno == EEXIST);

    ASSERT_ERR(open("/tmp/test-open/foo/bar", 0));
    ASSERT(errno == ENOTDIR);

    return EXIT_SUCCESS;
}
