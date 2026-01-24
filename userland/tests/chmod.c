#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    unlink("/tmp/test-chmod");

    errno = 0;
    ASSERT_ERR(chmod("nonexistent-file", 0755));
    ASSERT(errno == ENOENT);

    int fd = open("/tmp/test-chmod", O_CREAT | O_RDWR, 0644);
    ASSERT_OK(fd);

    struct stat st;
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_mode == (S_IFREG | 0644));

    ASSERT_OK(chmod("/tmp/test-chmod", 0755));
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_mode == (S_IFREG | 0755));

    ASSERT_OK(fchmod(fd, 0600));
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_mode == (S_IFREG | 0600));

    return EXIT_SUCCESS;
}
