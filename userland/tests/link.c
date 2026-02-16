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
        size_t n = ASSERT_OK(read(fd, p + total, count - total));
        if (n == 0)
            break;
        total += n;
    }
    return total;
}

static size_t write_all(int fd, const void* buf, size_t count) {
    const unsigned char* p = buf;
    size_t total = 0;
    while (total < count) {
        size_t n = ASSERT_OK(write(fd, p + total, count - total));
        if (n == 0)
            break;
        total += n;
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

    int fd = ASSERT_OK(open("/tmp/test-link-target", O_CREAT | O_RDWR, 0644));
    ASSERT(write_all(fd, "xxx", 3) == 3);

    ASSERT_OK(link("/tmp/test-link-target", "/tmp/test-link-hard"));
    ASSERT_OK(symlink("/tmp/test-link-target", "/tmp/test-link-sym"));

    char buf[4];

    int fd2 = ASSERT_OK(open("/tmp/test-link-hard", O_RDONLY));
    ASSERT(read_all(fd2, buf, 3) == 3);
    ASSERT(memcmp(buf, "xxx", 3) == 0);

    int fd3 = ASSERT_OK(open("/tmp/test-link-sym", O_RDONLY));
    ASSERT(read_all(fd3, buf, 3) == 3);
    ASSERT(memcmp(buf, "xxx", 3) == 0);

    return EXIT_SUCCESS;
}
