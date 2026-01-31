#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    unlink("/tmp/test-stat");
    int fd = open("/tmp/test-stat", O_CREAT | O_RDWR, 0644);
    ASSERT_OK(fd);

    ASSERT_OK(ftruncate(fd, 5));

    struct stat st;
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_size == 5);

    st = (struct stat){0};
    ASSERT_OK(fstatat(fd, "", &st, AT_EMPTY_PATH));
    ASSERT(st.st_size == 5);

    st = (struct stat){0};
    ASSERT_OK(fstatat(fd, NULL, &st, AT_EMPTY_PATH));
    ASSERT(st.st_size == 5);

    errno = 0;
    ASSERT_ERR(fstatat(fd, "", &st, 0));
    ASSERT(errno == ENOENT);

    struct statx stx;
    ASSERT_OK(statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx));
    ASSERT(stx.stx_size == 5);

    stx = (struct statx){0};
    ASSERT_OK(statx(fd, NULL, AT_EMPTY_PATH, STATX_BASIC_STATS, &stx));
    ASSERT(stx.stx_size == 5);

    errno = 0;
    ASSERT_ERR(statx(fd, "", 0, STATX_BASIC_STATS, &stx));
    ASSERT(errno == ENOENT);

    ASSERT_OK(close(fd));

    return EXIT_SUCCESS;
}
