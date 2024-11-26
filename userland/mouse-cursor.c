#include "moused.h"
#include <errno.h>
#include <extra.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CURSOR_WIDTH 8
#define CURSOR_HEIGHT 14
#define CURSOR_COLOR 0xf0f0f0

static const char mask[] = "x......."
                           "xx......"
                           "xxx....."
                           "xxxx...."
                           "xxxxx..."
                           "xxxxxx.."
                           "xxxxxxx."
                           "xxxxxxxx"
                           "xxxxxxx."
                           "xxxxx..."
                           "x...xx.."
                           "....xx.."
                           ".....xx."
                           ".....xx.";

static uintptr_t fb_addr;
static struct fb_fix_screeninfo fb_fix;
static struct fb_var_screeninfo fb_var;
static uint32_t cursor_x;
static uint32_t cursor_y;
static size_t visible_width;
static size_t visible_height;
static uint32_t fb_buf[CURSOR_WIDTH * CURSOR_HEIGHT];

static void move_cursor_to(uint32_t x, uint32_t y) {
    cursor_x = MIN(fb_var.xres - 1, x);
    cursor_y = MIN(fb_var.yres - 1, y);
    visible_width = MIN(CURSOR_WIDTH, fb_var.xres - cursor_x);
    visible_height = MIN(CURSOR_HEIGHT, fb_var.yres - cursor_y);

    uintptr_t origin_addr =
        fb_addr + cursor_x * sizeof(uint32_t) + cursor_y * fb_fix.line_length;

    // save framebuffer content to fb_buf
    uintptr_t row_addr = origin_addr;
    uint32_t* dest = fb_buf;
    for (size_t y = 0; y < visible_height; ++y) {
        memcpy32(dest, (uint32_t*)row_addr, visible_width);
        row_addr += fb_fix.line_length;
        dest += visible_width;
    }

    // draw cursor
    row_addr = origin_addr;
    const char* row_mask = mask;
    for (size_t y = 0; y < visible_height; ++y) {
        uint32_t* pixel = (uint32_t*)row_addr;
        const char* mask_for_pixel = row_mask;
        for (size_t x = 0; x < visible_width; ++x) {
            if (*mask_for_pixel++ == 'x')
                *pixel = CURSOR_COLOR;
            ++pixel;
        }
        row_addr += fb_fix.line_length;
        row_mask += CURSOR_WIDTH;
    }
}

static void restore_fb(void) {
    uintptr_t row_addr =
        fb_addr + cursor_x * sizeof(uint32_t) + cursor_y * fb_fix.line_length;
    uint32_t* src = fb_buf;
    for (size_t y = 0; y < visible_height; ++y) {
        memcpy32((uint32_t*)row_addr, src, visible_width);
        row_addr += fb_fix.line_length;
        src += visible_width;
    }
}

int main(void) {
    int fb_fd = open("/dev/fb0", O_RDWR);
    if (fb_fd < 0) {
        if (errno == ENOENT)
            return EXIT_SUCCESS;
        perror("open");
        return EXIT_FAILURE;
    }
    if (ioctl(fb_fd, FBIOGET_FSCREENINFO, &fb_fix) < 0) {
        perror("ioctl");
        close(fb_fd);
        return EXIT_FAILURE;
    }
    if (ioctl(fb_fd, FBIOGET_VSCREENINFO, &fb_var) < 0) {
        perror("ioctl");
        close(fb_fd);
        return EXIT_FAILURE;
    }
    if (fb_var.bits_per_pixel != 32) {
        dprintf(STDERR_FILENO, "Unsupported bit depth\n");
        close(fb_fd);
        return EXIT_FAILURE;
    }
    void* fb = mmap(NULL, fb_fix.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED,
                    fb_fd, 0);
    if (fb == MAP_FAILED) {
        perror("mmap");
        close(fb_fd);
        return EXIT_FAILURE;
    }
    close(fb_fd);
    fb_addr = (uintptr_t)fb;

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    struct sockaddr_un addr = {AF_UNIX, "/tmp/moused-socket"};
    if (connect(sockfd, (const struct sockaddr*)&addr,
                sizeof(struct sockaddr_un)) < 0) {
        perror("connect");
        close(sockfd);
        return EXIT_FAILURE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(sockfd);
        return EXIT_FAILURE;
    }
    if (pid > 0)
        exit(0);

    move_cursor_to(fb_var.xres / 2, fb_var.yres / 2);

    struct moused_event event;
    for (;;) {
        ssize_t nread = read(sockfd, &event, sizeof(struct moused_event));
        if (nread == 0) {
            close(sockfd);
            return EXIT_FAILURE;
        }
        if (nread < 0) {
            perror("read");
            close(sockfd);
            return EXIT_FAILURE;
        }
        restore_fb();
        move_cursor_to(event.x, event.y);
    }
}
