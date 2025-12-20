#include "moused.h"
#include <common/bytes.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <math.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static uint32_t* fb;
static struct fb_fix_screeninfo fb_fix;
static struct fb_var_screeninfo fb_var;

// based on "A Fast Bresenham Type Algorithm For Drawing Ellipses"
// https://dai.fmph.uniba.sk/upload/0/01/Ellipse.pdf

static void draw_ellipse_part(uint32_t cx, uint32_t cy, uint32_t x, uint32_t y,
                              uint32_t color) {
    unsigned char* s = (unsigned char*)(fb + cx - x);
    size_t n = 2 * x + 1;
    memset32((uint32_t*)(s + fb_fix.line_length * (cy - y)), color, n);
    memset32((uint32_t*)(s + fb_fix.line_length * (cy + y)), color, n);
}

static void fill_ellipse(uint32_t cx, uint32_t cy, uint32_t x_radius,
                         uint32_t y_radius, uint32_t color) {
    uint32_t two_a_square = 2 * x_radius * x_radius;
    uint32_t two_b_square = 2 * y_radius * y_radius;

    uint32_t x = x_radius;
    uint32_t y = 0;
    int32_t x_change = y_radius * y_radius * (1 - 2 * x_radius);
    int32_t y_change = x_radius * x_radius;
    int32_t ellipse_error = 0;
    int32_t stopping_x = two_b_square * x_radius;
    int32_t stopping_y = 0;
    while (stopping_x >= stopping_y) {
        draw_ellipse_part(cx, cy, x, y, color);
        ++y;
        stopping_y += two_a_square;
        ellipse_error += y_change;
        y_change += two_a_square;
        if (2 * ellipse_error + x_change > 0) {
            --x;
            stopping_x -= two_b_square;
            ellipse_error += x_change;
            x_change += two_b_square;
        }
    }

    x = 0;
    y = y_radius;
    x_change = y_radius * y_radius;
    y_change = x_radius * x_radius * (1 - 2 * y_radius);
    ellipse_error = 0;
    stopping_x = 0;
    stopping_y = two_a_square * y_radius;
    while (stopping_x <= stopping_y) {
        draw_ellipse_part(cx, cy, x, y, color);
        ++x;
        stopping_x += two_b_square;
        ellipse_error += x_change;
        x_change += two_b_square;
        if (2 * ellipse_error + y_change > 0) {
            --y;
            stopping_y -= two_a_square;
            ellipse_error += y_change;
            y_change += two_a_square;
        }
    }
}

static void draw_eyeball(unsigned i, uint32_t mouse_x, uint32_t mouse_y) {
    uint32_t eye_width = fb_var.xres / 2;
    uint32_t eye_height = fb_var.yres;
    uint32_t eye_x = eye_width * i;
    uint32_t eye_y = 0;

    uint32_t margin = eye_width / 25;
    eye_width -= margin * 2;
    eye_x += margin;

    uint32_t padding_x = eye_width / 11;
    padding_x = MAX(padding_x, 1);
    eye_width -= padding_x * 2;
    eye_x += padding_x;

    uint32_t padding_y = eye_height / 11;
    padding_y = MAX(padding_y, 1);
    eye_height -= padding_y * 2;
    eye_y += padding_y;

    uint32_t eye_cx = eye_x + eye_width / 2;
    uint32_t eye_cy = eye_y + eye_height / 2;
    fill_ellipse(eye_cx, eye_cy, eye_width / 2, eye_height / 2, 0xffffff);

    int32_t dx = mouse_x - eye_cx;
    int32_t dy = mouse_y - eye_cy;
    double dist = sqrt((double)dx * dx + (double)dy * dy);
    uint32_t pupil_cx = eye_cx;
    uint32_t pupil_cy = eye_cy;
    if (dist != 0) {
        uint32_t w2 = eye_width * eye_width;
        uint32_t h2 = eye_height * eye_height;
        double d2 = 0;
        if (dx != 0 && abs(dx) >= abs(dy)) {
            double slope = (double)dy / dx;
            double s2 = slope * slope;
            d2 = (s2 + 1) / (1.0 / w2 + s2 / h2);
        } else if (dy != 0 && abs(dy) >= abs(dx)) {
            double slope = (double)dx / dy;
            double s2 = slope * slope;
            d2 = (s2 + 1) / (s2 / w2 + 1.0 / h2);
        }
        double scale = 0.25 * sqrt(d2) / dist;
        scale = MIN(scale, 1.0);
        pupil_cx = eye_cx + (uint32_t)(dx * scale);
        pupil_cy = eye_cy + (uint32_t)(dy * scale);
    }
    fill_ellipse(pupil_cx, pupil_cy, eye_width / 10, eye_height / 10, 0);
}

static void draw(uint32_t mouse_x, uint32_t mouse_y) {
    draw_eyeball(0, mouse_x, mouse_y);
    draw_eyeball(1, mouse_x, mouse_y);
}

int main(void) {
    int fb_fd = open("/dev/fb0", O_RDWR);
    if (fb_fd < 0) {
        if (errno == ENOENT) {
            puts("Framebuffer is not available");
            return EXIT_FAILURE;
        }
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
        dprintf(STDERR_FILENO, "Unsupported bpp\n");
        return EXIT_FAILURE;
    }
    fb = mmap(NULL, fb_fix.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd,
              0);
    if (fb == MAP_FAILED) {
        perror("mmap");
        close(fb_fd);
        return EXIT_FAILURE;
    }
    close(fb_fd);

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

    struct moused_event event = {
        .x = fb_var.xres / 2,
        .y = fb_var.yres / 2,
    };
    for (;;) {
        draw(event.x, event.y);

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
    }
}
