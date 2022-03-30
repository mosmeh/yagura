#include "stdlib.h"
#include "syscall.h"
#include <common/extra.h>
#include <kernel/api/err.h>
#include <kernel/api/fb.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/hid.h>
#include <kernel/api/mman.h>

static noreturn void child1(void) {
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

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT(IS_OK(sockfd));
    sockaddr_un addr = {AF_UNIX, "/tmp/uds"};
    printf("client1: connecting\n");
    ASSERT(IS_OK(connect(sockfd, (const sockaddr*)&addr, sizeof(sockaddr_un))));
    printf("client1: connected\n");
    mouse_packet packet;
    int32_t x = info.width / 2;
    int32_t y = info.height / 2;
    for (;;) {
        ssize_t nread = read(sockfd, &packet, sizeof(mouse_packet));
        ASSERT(nread == sizeof(mouse_packet));
        printf("client1: recv dx=%d dy=%d\n", packet.dx, packet.dy);
        x = MIN((int32_t)(info.width - 1), MAX(0, x + packet.dx));
        y = MIN((int32_t)(info.height - 1), MAX(0, y - packet.dy));
        uint32_t color = 0xffffff;
        if (packet.buttons & MOUSE_BUTTON_LEFT)
            color &= 0xff00ff;
        if (packet.buttons & MOUSE_BUTTON_RIGHT)
            color &= 0x00ffff;
        for (int i = x; i < MIN(x + 5, (int32_t)(info.width - 1)); ++i)
            for (int j = y; j < MIN(y + 5, (int32_t)(info.height - 1)); ++j)
                fb[i + info.width * j] = color;
    }
    ASSERT(IS_OK(close(fb_fd)));
    ASSERT(IS_OK(close(sockfd)));

    exit(0);
}

static noreturn void child2(void) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT(IS_OK(sockfd));
    sockaddr_un addr = {AF_UNIX, "/tmp/uds"};
    printf("client2: connecting\n");
    ASSERT(IS_OK(connect(sockfd, (const sockaddr*)&addr, sizeof(sockaddr_un))));
    printf("client2: connected\n");
    for (;;) {
        int i;
        ssize_t nread = read(sockfd, &i, sizeof(int));
        ASSERT(nread == sizeof(int));
        printf("client2: recv %d\n", i);
    }
    ASSERT(IS_OK(close(sockfd)));
    exit(0);
}

void _start(void) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT(IS_OK(sockfd));
    sockaddr_un addr = {AF_UNIX, "/tmp/uds"};
    ASSERT(IS_OK(bind(sockfd, (const sockaddr*)&addr, sizeof(sockaddr_un))));
    ASSERT(IS_OK(listen(sockfd, 5)));
    printf("server: listening\n");

    if (fork() == 0)
        child1();

    int peer_fd1 = accept(sockfd, NULL, NULL);
    printf("server: accepted (1)\n");
    ASSERT(IS_OK(peer_fd1));

    if (fork() == 0)
        child2();
    if (fork() == 0)
        child2();

    int peer_fd2 = accept(sockfd, NULL, NULL);
    printf("server: accepted (2)\n");
    ASSERT(IS_OK(peer_fd2));

    int peer_fd3 = accept(sockfd, NULL, NULL);
    printf("server: accepted (2)\n");
    ASSERT(IS_OK(peer_fd2));

    int ps_fd = open("/dev/psaux", O_RDWR);
    mouse_packet packet;
    int i = 0;
    for (;;) {
        ssize_t nread = read(ps_fd, &packet, sizeof(mouse_packet));
        if (nread == 0) {
            sched_yield();
            continue;
        }
        ++i;
        ASSERT(nread == sizeof(mouse_packet));
        ASSERT(write(peer_fd1, &packet, nread) == nread);
        printf("server: send1 dx=%d dy=%d\n", packet.dx, packet.dy);
        ASSERT(write(peer_fd2, &i, sizeof(int)) == sizeof(int));
        ASSERT(write(peer_fd3, &i, sizeof(int)) == sizeof(int));
        printf("server: send2&3 %d\n", i);
    }

    ASSERT(IS_OK(close(sockfd)));
    ASSERT(IS_OK(close(ps_fd)));

    exit(0);
}
