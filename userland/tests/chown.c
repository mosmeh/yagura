#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    unlink("/tmp/test-chown");

    errno = 0;
    ASSERT_ERR(chown("nonexistent-file", 1000, 1000));
    ASSERT(errno == ENOENT);

    int fd = open("/tmp/test-chown", O_CREAT | O_RDWR, 0644);
    ASSERT_OK(fd);

    ASSERT_OK(chown("/tmp/test-chown", 1000, 1001));
    struct stat st;
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_uid == 1000);
    ASSERT(st.st_gid == 1001);

    ASSERT_OK(fchown(fd, 2000, 2001));
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_uid == 2000);
    ASSERT(st.st_gid == 2001);

    ASSERT_OK(fchown(fd, -1, 3001));
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_uid == 2000);
    ASSERT(st.st_gid == 3001);

    ASSERT_OK(fchown(fd, 4000, -1));
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_uid == 4000);
    ASSERT(st.st_gid == 3001);

    ASSERT_OK(fchmod(fd, 0644 | S_ISUID | S_ISGID));
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_mode == (S_IFREG | 0644 | S_ISUID | S_ISGID));
    ASSERT_OK(fchown(fd, -1, -1));
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_mode == (S_IFREG | 0644 | S_ISGID));

    ASSERT_OK(fchmod(fd, 0755 | S_ISUID | S_ISGID));
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_mode == (S_IFREG | 0755 | S_ISUID | S_ISGID));
    ASSERT_OK(fchown(fd, -1, -1));
    ASSERT_OK(fstat(fd, &st));
    ASSERT(st.st_mode == (S_IFREG | 0755));

    return EXIT_SUCCESS;
}
