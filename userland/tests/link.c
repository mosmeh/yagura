#include "../io.h"
#include <common/string.h>
#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    unlink("/tmp/test-link-target");
    unlink("/tmp/test-link-target2");
    unlink("/tmp/test-link-hard");
    unlink("/tmp/test-link-hard2");
    unlink("/tmp/test-link-sym");
    unlink("/tmp/test-link-sym2");
    unlink("/tmp/test-link-sym3");
    unlink("/tmp/test-link-sym4");
    unlink("/tmp/test-link-sym5");
    unlink("/tmp/test-link-dangling-sym");
    unlink("/tmp/test-link-dangling-sym2");
    rmdir("/tmp/test-link-dir");
    rmdir("/tmp/test-link-rename-dir");
    unlink("/tmp/test-link-loop");

    ASSERT_ERRNO(link("", "/tmp/test-link-hard"), ENOENT);
    ASSERT_ERRNO(symlink("", "/tmp/test-link"), ENOENT);

    ASSERT_ERRNO(link("/tmp/no-such-file", "/tmp/test-link-hard"), ENOENT);

    {
        int fd = ASSERT_OK(
            open("/tmp/test-link-target", O_CREAT | O_RDWR | O_TRUNC, 0644));
        ASSERT_OK(write_all(fd, "xxx", 3));
        ASSERT_OK(close(fd));
    }

    ASSERT_OK(symlink("/tmp/no-such-file", "/tmp/test-link-dangling-sym"));
    ASSERT_ERRNO(link("/tmp/test-link-target", "/tmp/test-link-dangling-sym"),
                 EEXIST);
    ASSERT_ERRNO(
        symlink("/tmp/test-link-target", "/tmp/test-link-dangling-sym"),
        EEXIST);
    ASSERT_ERRNO(mkdir("/tmp/test-link-dangling-sym", 0755), EEXIST);
    ASSERT_ERRNO(mknod("/tmp/test-link-dangling-sym", S_IFREG | 0644, 0),
                 EEXIST);
    ASSERT_ERRNO(access("/tmp/test-link-dangling-sym", F_OK), ENOENT);

    ASSERT_OK(
        symlink("/tmp/test-link-target2", "/tmp/test-link-dangling-sym2"));
    ASSERT_ERRNO(open("/tmp/test-link-dangling-sym2", O_CREAT | O_EXCL, 0644),
                 EEXIST);
    ASSERT_OK(open("/tmp/test-link-dangling-sym2", O_CREAT, 0644));
    ASSERT_OK(access("/tmp/test-link-target2", F_OK));

    ASSERT_OK(link("/tmp/test-link-target", "/tmp/test-link-hard"));
    ASSERT_ERRNO(link("/tmp/test-link-target", "/tmp/test-link-hard"), EEXIST);
    ASSERT_OK(symlink("/tmp/test-link-target", "/tmp/test-link-sym"));
    ASSERT_ERRNO(symlink("/tmp/test-link-target", "/tmp/test-link-sym"),
                 EEXIST);

    ASSERT_OK(mkdir("/tmp/test-link-dir", 0755));
    ASSERT_ERRNO(link("/tmp/test-link-dir", "/tmp/test-link-dir-hard"), EPERM);
    ASSERT_OK(symlink("/tmp/test-link-dir", "/tmp/test-link-dir-sym"));

    char buf[4];
    {
        int fd = ASSERT_OK(open("/tmp/test-link-hard", O_RDONLY));
        ASSERT_OK(read_exact(fd, buf, 3));
        ASSERT_OK(close(fd));
        ASSERT(memcmp(buf, "xxx", 3) == 0);
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-link-sym", O_RDONLY));
        ASSERT_OK(read_exact(fd, buf, 3));
        ASSERT_OK(close(fd));
        ASSERT(memcmp(buf, "xxx", 3) == 0);
    }

    ASSERT_OK(unlink("/tmp/test-link-hard"));
    ASSERT_OK(unlink("/tmp/test-link-sym"));

    ASSERT_ERRNO(rmdir("/tmp/test-link-dir-sym"), ENOTDIR);
    ASSERT_OK(unlink("/tmp/test-link-dir-sym"));

    ASSERT_OK(access("/tmp/test-link-target", F_OK));
    ASSERT_OK(access("/tmp/test-link-dir", F_OK));

    {
        int fd = ASSERT_OK(open("/tmp/test-link-rename-target",
                                O_CREAT | O_RDWR | O_TRUNC, 0644));
        ASSERT_OK(write_all(fd, "yyy", 3));
        ASSERT_OK(close(fd));
        ASSERT_OK(symlink("/tmp/test-link-target", "/tmp/test-link-sym2"));
        ASSERT_OK(
            rename("/tmp/test-link-rename-target", "/tmp/test-link-sym2"));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-link-target", O_RDONLY));
        ASSERT_OK(read_exact(fd, buf, 3));
        ASSERT_OK(close(fd));
        ASSERT(memcmp(buf, "xxx", 3) == 0);
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-link-sym2", O_RDONLY));
        ASSERT_OK(read_exact(fd, buf, 3));
        ASSERT_OK(close(fd));
        ASSERT(memcmp(buf, "yyy", 3) == 0);
    }

    ASSERT_OK(mkdir("/tmp/test-link-rename-dir", 0755));
    ASSERT_OK(symlink("/tmp/test-link-target", "/tmp/test-link-sym3"));
    ASSERT_ERRNO(rename("/tmp/test-link-rename-dir", "/tmp/test-link-sym3"),
                 ENOTDIR);

    {
        int fd = ASSERT_OK(open("/tmp/test-link-rename-target2",
                                O_CREAT | O_RDWR | O_TRUNC, 0644));
        ASSERT_OK(write_all(fd, "zzz", 3));
        ASSERT_OK(close(fd));
    }
    ASSERT_OK(symlink("/tmp/test-link-rename-target2", "/tmp/test-link-sym4"));
    ASSERT_OK(rename("/tmp/test-link-sym4", "/tmp/test-link-sym5"));
    ASSERT_ERRNO(access("/tmp/test-link-sym4", F_OK), ENOENT);
    ASSERT_OK(access("/tmp/test-link-rename-target2", F_OK));
    {
        int fd = ASSERT_OK(open("/tmp/test-link-sym5", O_RDONLY));
        ASSERT_OK(read_exact(fd, buf, 3));
        ASSERT_OK(close(fd));
        ASSERT(memcmp(buf, "zzz", 3) == 0);
    }

    ASSERT_OK(link("/tmp/test-link-sym5", "/tmp/test-link-hard2"));
    size_t len = ASSERT_OK(readlink("/tmp/test-link-hard2", buf, sizeof(buf)));
    ASSERT(memcmp(buf, "/tmp/test-link-rename-target2", len) == 0);

    ASSERT_ERRNO(link("/tmp/test-link-loop", "/tmp/test-link-loop"), ENOENT);
    ASSERT_OK(symlink("/tmp/test-link-loop", "/tmp/test-link-loop"));
    ASSERT_ERRNO(access("/tmp/test-link-loop", F_OK), ELOOP);

    return EXIT_SUCCESS;
}
