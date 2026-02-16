#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    mode_t original_umask = ASSERT_OK(umask(0243));
    {
        unlink("/tmp/test-chmod");
        int fd = ASSERT_OK(open("/tmp/test-chmod", O_CREAT | O_RDWR, 0777));
        struct stat st;
        ASSERT_OK(fstat(fd, &st));
        ASSERT(st.st_mode == (S_IFREG | (0777 & ~0243)));
        ASSERT_OK(close(fd));
    }
    {
        rmdir("/tmp/test-chmod-dir");
        ASSERT_OK(mkdir("/tmp/test-chmod-dir", 0777));
        struct stat st;
        ASSERT_OK(stat("/tmp/test-chmod-dir", &st));
        ASSERT(st.st_mode == (S_IFDIR | (0777 & ~0243)));
    }
    ASSERT_OK(umask(original_umask));
    return EXIT_SUCCESS;
}
