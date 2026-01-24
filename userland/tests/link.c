#include <common/string.h>
#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <unistd.h>

static size_t read_all(int fd, void* buf, size_t count) {
    unsigned char* p = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, p + total, count - total);
        ASSERT_OK(n);
        total += n;
    }
    return total;
}

static size_t write_all(int fd, const void* buf, size_t count) {
    const unsigned char* p = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t nwritten = write(fd, p + total, count - total);
        ASSERT_OK(nwritten);
        total += nwritten;
    }
    return total;
}

int main(void) {
    unlink("/tmp/test-link-hard");
    unlink("/tmp/test-link-sym");

    errno = 0;
    ASSERT_ERR(link("", "/tmp/test-link-hard"));
    ASSERT(errno == ENOENT);

    errno = 0;
    ASSERT_ERR(symlink("", "/tmp/test-link"));
    ASSERT(errno == ENOENT);

    int fd = open("/tmp/test-link-target", O_CREAT | O_RDWR, 0644);
    ASSERT_OK(fd);
    ASSERT(write_all(fd, "xxx", 3) == 3);

    ASSERT_OK(link("/tmp/test-link-target", "/tmp/test-link-hard"));
    ASSERT_OK(symlink("/tmp/test-link-target", "/tmp/test-link-sym"));

    char buf[4];

    int fd2 = open("/tmp/test-link-hard", O_RDONLY);
    ASSERT_OK(fd2);
    ASSERT(read_all(fd2, buf, 3) == 3);
    ASSERT(memcmp(buf, "xxx", 3) == 0);

    int fd3 = open("/tmp/test-link-sym", O_RDONLY);
    ASSERT_OK(fd3);
    ASSERT(read_all(fd3, buf, 3) == 3);
    ASSERT(memcmp(buf, "xxx", 3) == 0);

    return EXIT_SUCCESS;
}
