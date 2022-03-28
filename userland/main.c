#include "kernel/api/socket.h"
#include "stdlib.h"
#include "syscall.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/api/fb.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/hid.h>
#include <kernel/api/mman.h>
#include <kernel/api/syscall.h>
#include <kernel/boot_defs.h>

static void read_file(const char* filename) {
    int fd = open(filename, O_RDWR);
    ASSERT(IS_OK(fd));
    const size_t size = 1024;
    char buf1[size];
    ssize_t nread = read(fd, buf1, size);
    ASSERT(IS_OK(nread));

    int fd2 = open(filename, O_RDWR);
    ASSERT(IS_OK(fd2));
    char buf2[size];
    size_t pos = 0;
    for (;;) {
        ssize_t nread = read(fd2, buf2 + pos, 1);
        if (nread == 0)
            break;
        pos += nread;
    }

    ASSERT(IS_OK(close(fd)));
    ASSERT(IS_OK(close(fd2)));

    ASSERT(!strcmp(buf1, buf2));
}

static noreturn void child_process_entry(void) {
    pid_t pid_before = getpid();
    ASSERT(IS_OK(pid_before));

    pid_t ret = fork();
    ASSERT(IS_OK(ret));
    pid_t pid_after = getpid();
    ASSERT(IS_OK(pid_after));

    if (ret == 0) {
        ASSERT(pid_after > pid_before);
    } else {
        ASSERT(pid_after == pid_before);
        ASSERT(ret > pid_before);
    }

    malloc_ctx ctx;
    malloc_init(&ctx);

    const size_t size = PAGE_SIZE * 2 + 128;
    void* buf = malloc(&ctx, size);
    memset(buf, 42, size);
    ASSERT(buf);
    free(&ctx, buf);

    exit(0);
}

static void list_dir(malloc_ctx* ctx, const char* path) {
    int fd = open(path, O_RDWR);
    ASSERT(IS_OK(fd));
    uintptr_t buf = (uintptr_t)malloc(ctx, 1024);
    ASSERT(buf);
    ssize_t nread = syscall(SYS_getdents, fd, buf, 1024);
    ASSERT(IS_OK(nread));
    for (size_t pos = 0; pos < (size_t)nread;) {
        dirent* dent = (dirent*)(buf + pos);
        printf("name=_%s_ type=%u ino=%u\n", dent->name, dent->type, dent->ino);
        pos += dent->record_len;
    }
    free(ctx, (void*)buf);
    ASSERT(IS_OK(close(fd)));
}

static int create_file(const char* pathname, int extra_flags) {
    int fd = open(pathname, extra_flags | O_RDWR | O_CREAT, 0777);
    if (IS_ERR(fd))
        return fd;
    return close(fd);
}

int userland_main(void) {
    pid_t ret = fork();
    ASSERT(IS_OK(ret));
    if (ret == 0)
        child_process_entry();

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT(IS_OK(sockfd));
    sockaddr_un addr = {AF_UNIX, "/tmp/uds"};
    ASSERT(IS_OK(bind(sockfd, (const sockaddr*)&addr, sizeof(sockaddr_un))));

    malloc_ctx ctx;
    malloc_init(&ctx);
    ASSERT(IS_OK(create_file("/tmp/aoo", 0)));
    ASSERT(IS_OK(create_file("/tmp/eeee", 0)));
    ASSERT(IS_OK(create_file("/tmp/eeee", 0)));
    ASSERT(create_file("/tmp/eeee", O_EXCL) == -EEXIST);
    ASSERT(create_file("/tmp/eeee/aa", 0) == -ENOTDIR);
    ASSERT(create_file("/tmp/aa/gew", 0) == -ENOENT);
    {
        int fd_new = open("/tmp/hoge", O_RDWR | O_CREAT, 0777);
        ASSERT(IS_OK(fd_new));
        char buf[1024];
        int len = sprintf(buf, "foobar");
        for (int i = 0; i < 2; ++i)
            ASSERT(IS_OK(write(fd_new, buf, len)));
        ASSERT(IS_OK(close(fd_new)));
    }
    {
        int fd_new = open("/tmp/hoge", O_RDWR);
        ASSERT(IS_OK(fd_new));
        char buf[1024];
        ASSERT(IS_OK(read(fd_new, buf, 1024)));
        ASSERT(IS_OK(close(fd_new)));
        printf("%s\n", buf);
    }
    list_dir(&ctx, "/tmp/");

    read_file("/hello.txt");
    read_file("/foo/bar/baz/foo.txt");
    list_dir(&ctx, "/");

    int fd = open("/dev/ttyS1", O_RDWR);
    ASSERT(IS_OK(fd));
    ASSERT(IS_OK(close(fd)));

    int fb_fd = open("/dev/fb0", O_RDWR);
    ASSERT(IS_OK(fb_fd));
    fb_info info;
    ASSERT(IS_OK(ioctl(fb_fd, FBIOGET_INFO, &info)));
    uint32_t* fb =
        (uint32_t*)mmap(NULL, info.pitch * info.height, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fb_fd, 0);
    ASSERT(fb != MAP_FAILED);
    for (size_t y = 0; y < info.height; ++y)
        for (size_t x = 0; x < info.width; ++x)
            fb[x + info.width * y] =
                ((100000 * x / (info.width - 1) / 1000) << 16) +
                ((100000 * y / (info.height - 1) / 1000) << 8);

    int ps_fd = open("/dev/psaux", O_RDWR);
    int32_t x = info.width / 2;
    int32_t y = info.height / 2;
    mouse_packet packet;
    for (;;) {
        ssize_t nread = read(ps_fd, &packet, sizeof(mouse_packet));
        if (nread == 0)
            continue;
        ASSERT(nread == sizeof(mouse_packet));
        x = MIN((int32_t)(info.width - 1), MAX(0, x + packet.dx));
        y = MIN((int32_t)(info.height - 1), MAX(0, y - packet.dy));
        fb[x + info.width * y] =
            (packet.buttons & MOUSE_BUTTON_LEFT) ? 0xff0000 : 0xffffff;
    }

    ASSERT(IS_OK(close(fb_fd)));
    ASSERT(IS_OK(close(ps_fd)));

    return 123;
}
