#include "moused.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <panic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static bool get_fb_info(struct fb_var_screeninfo* out_fb_var) {
    int fd = open("/dev/fb0", 0);
    if (fd < 0)
        return false;
    if (ioctl(fd, FBIOGET_VSCREENINFO, out_fb_var) < 0) {
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

static int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        perror("fcntl");
        return flags;
    }
    flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (flags < 0)
        perror("fcntl");
    return flags;
}

#define MAX_NUM_CONNECTIONS 8

static int sockfd = -1;
static int mouse_fd = -1;
static size_t width = 640;
static size_t height = 480;
static int32_t cursor_x = 0;
static int32_t cursor_y = 0;
static struct pollfd pollfds[MAX_NUM_CONNECTIONS + 2];

static int handle_new_connection(void) {
    int fd = accept(sockfd, NULL, NULL);
    if (fd < 0) {
        if (errno == EAGAIN)
            return 0;
        perror("accept");
        return -1;
    }
    if (set_non_blocking(fd) < 0) {
        close(fd);
        return -1;
    }
    for (size_t i = 0; i < MAX_NUM_CONNECTIONS; ++i) {
        if (pollfds[2 + i].fd < 0) {
            pollfds[2 + i].fd = fd;
            return 0;
        }
    }
    return 0;
}

static int broadcast_event(void) {
    for (;;) {
        unsigned char buf[3];
        ssize_t nread = read(mouse_fd, &buf, sizeof(buf));
        if (nread < 0) {
            if (errno == EAGAIN)
                return 0;
            perror("read");
            return -1;
        }
        if (nread != sizeof(buf)) {
            dprintf(STDERR_FILENO, "moused: short read from mouse device\n");
            return -1;
        }

        uint8_t buttons = buf[0] & 7;
        int16_t dx = buf[1];
        int16_t dy = buf[2];
        if (dx && (buf[0] & 0x10))
            dx -= 0x100;
        if (dy && (buf[0] & 0x20))
            dy -= 0x100;
        if (buf[0] & 0xc0)
            dx = dy = 0;
        dy = -dy;

        cursor_x = MAX(0, MIN((int32_t)(width - 1), cursor_x + dx));
        cursor_y = MAX(0, MIN((int32_t)(height - 1), cursor_y + dy));

        struct moused_event moused_event = {
            .x = cursor_x,
            .y = cursor_y,
            .dx = dx,
            .dy = dy,
            .buttons = buttons,
        };
        for (size_t i = 0; i < MAX_NUM_CONNECTIONS; ++i) {
            int* fd = &pollfds[2 + i].fd;
            if (*fd < 0)
                continue;
            ssize_t nwritten =
                write(*fd, &moused_event, sizeof(struct moused_event));
            if (nwritten < 0 && errno != EAGAIN)
                *fd = -1;
        }
    }
}

int main(void) {
    mouse_fd = open("/dev/psaux", O_RDONLY);
    if (mouse_fd < 0) {
        if (errno == ENOENT) {
            // PS/2 mouse is disabled
            return 0;
        }
        perror("open");
        goto fail;
    }
    if (set_non_blocking(mouse_fd) < 0)
        goto fail;

    struct fb_var_screeninfo fb_var;
    if (get_fb_info(&fb_var)) {
        width = fb_var.xres;
        height = fb_var.yres;
        cursor_x = width / 2;
        cursor_y = height / 2;
    }

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        goto fail;
    }
    if (set_non_blocking(sockfd) < 0)
        goto fail;
    struct sockaddr_un addr = {AF_UNIX, "/tmp/moused-socket"};
    if (bind(sockfd, (const struct sockaddr*)&addr,
             sizeof(struct sockaddr_un)) < 0) {
        perror("bind");
        goto fail;
    }
    if (listen(sockfd, MAX_NUM_CONNECTIONS) < 0) {
        perror("listen");
        goto fail;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        goto fail;
    }
    if (pid > 0)
        exit(0);

    pollfds[0] = (struct pollfd){.fd = sockfd, .events = POLLIN};
    pollfds[1] = (struct pollfd){.fd = mouse_fd, .events = POLLIN};

    for (size_t i = 0; i < MAX_NUM_CONNECTIONS; ++i) {
        pollfds[2 + i] = (struct pollfd){
            .fd = -1,
        };
    }

    for (;;) {
        if (poll(pollfds, 2 + MAX_NUM_CONNECTIONS, -1) < 0) {
            perror("poll");
            goto fail;
        }
        for (size_t i = 0; i < MAX_NUM_CONNECTIONS; ++i) {
            if (pollfds[2 + i].revents & POLLHUP)
                pollfds[2 + i].fd = -1;
        }
        if (pollfds[0].revents & POLLIN) {
            if (handle_new_connection() < 0)
                goto fail;
        }
        if (pollfds[1].revents & POLLIN) {
            if (broadcast_event() < 0)
                goto fail;
        }
    }

fail:
    if (mouse_fd >= 0)
        close(mouse_fd);
    if (sockfd >= 0)
        close(sockfd);
    return EXIT_FAILURE;
}
