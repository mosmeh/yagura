#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/fb.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/mman.h>
#include <math.h>

#define MAX_ITER 100
#define X_START -3.0
#define X_END 1.5
#define Y_START -1.75
#define Y_END 1.75

#define LN2 0.693147180559945309417

static double mandelbrot(double x0, double y0) {
    double x = 0;
    double y = 0;
    double x2 = 0;
    double y2 = 0;
    size_t iter = 0;

    for (; x2 + y2 <= 4; ++iter) {
        y = 2 * x * y + y0;
        x = x2 - y2 + x0;
        x2 = x * x;
        y2 = y * y;
        if (iter >= MAX_ITER)
            return iter;
    }

    double lz = sqrt(x * x + y * y) / 2;
    return 1 + iter + log2(lz / LN2);
}

static uint32_t calc_pixel_value(double x0, double y0) {
    double iter = mandelbrot(x0, y0);
    if (iter >= MAX_ITER)
        return 0;

    double hue;
    {
        unsigned int_part = (unsigned)iter;
        double frac_part = iter - int_part;
        double hue1 = (double)int_part / MAX_ITER;
        double hue2 = (int_part + 1.0) / MAX_ITER;
        if (hue1 >= 1)
            hue1 = 0;
        if (hue2 >= 1)
            hue2 = 0;
        hue = hue1 + frac_part * (hue2 - hue1);
    }

    double r = 1;
    double g = 1;
    double b = 1;
    {
        double h = hue * 6;
        unsigned int_part = (unsigned)h;
        double frac_part = h - int_part;
        switch (int_part) {
        case 1:
            r *= 1 - frac_part;
            b = 0;
            break;
        case 2:
            r = 0;
            b *= frac_part;
            break;
        case 3:
            r = 0;
            g *= 1 - frac_part;
            break;
        case 4:
            r *= frac_part;
            g = 0;
            break;
        case 5:
            g = 0;
            b *= 1 - frac_part;
            break;
        case 0:
        default:
            g *= frac_part;
            b = 0;
            break;
        }
    }

    return ((uint8_t)(r * 255) << 16) | ((uint8_t)(g * 255) << 8) |
           (uint8_t)(b * 255);
}

int main(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }
    struct fb_info fb_info;
    if (ioctl(fd, FBIOGET_INFO, &fb_info) < 0) {
        perror("ioctl");
        return EXIT_FAILURE;
    }
    void* fb = mmap(NULL, fb_info.pitch * fb_info.height,
                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (fb == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }
    close(fd);

    uintptr_t row_addr = (uintptr_t)fb;
    for (size_t y = 0; y < fb_info.height; ++y) {
        double y0 = (Y_END - Y_START) * y / fb_info.height + Y_START;

        uint32_t* pixel = (uint32_t*)row_addr;
        for (size_t x = 0; x < fb_info.width; ++x) {
            double x0 = (X_END - X_START) * x / fb_info.width + X_START;
            *pixel++ = calc_pixel_value(x0, y0);
        }

        row_addr += fb_info.pitch;
    }

    return EXIT_SUCCESS;
}