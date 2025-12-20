#include <common/integer.h>
#include <linux/kd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct font {
    unsigned width;
    unsigned height;
    unsigned char_count;
    unsigned char_size;
    unsigned char* data;
};

#define PSF1_MAGIC0 0x36
#define PSF1_MAGIC1 0x04

#define PSF1_MODE512 0x01
#define PSF1_MODEHASTAB 0x02
#define PSF1_MODEHASSEQ 0x04
#define PSF1_MAXMODE 0x05

#define PSF1_SEPARATOR 0xFFFF
#define PSF1_STARTSEQ 0xFFFE

struct psf1_header {
    unsigned char magic[2];
    unsigned char mode;
    unsigned char charsize;
};

NODISCARD static int load_psf1(struct font* font, unsigned char* buf,
                               size_t buf_size) {
    if (buf_size < sizeof(struct psf1_header))
        return -1;

    const struct psf1_header* header = (const struct psf1_header*)buf;
    if (header->magic[0] != PSF1_MAGIC0 || header->magic[1] != PSF1_MAGIC1)
        return -1;

    font->width = 8;
    font->height = font->char_size = header->charsize;
    font->char_count = (header->mode & PSF1_MODE512) ? 512 : 256;
    font->data = buf + sizeof(struct psf1_header);

    return 0;
}

#define PSF2_MAGIC 0x864ab572

#define PSF2_HAS_UNICODE_TABLE 0x01

#define PSF2_SEPARATOR 0xFF
#define PSF2_STARTSEQ 0xFE

struct psf2_header {
    unsigned magic;
    unsigned version;
    unsigned headersize;
    unsigned flags;
    unsigned numglyph;
    unsigned bytesperglyph;
    unsigned height;
    unsigned width;
};

NODISCARD static int load_psf2(struct font* font, unsigned char* buf,
                               size_t buf_size) {
    if (buf_size < sizeof(struct psf2_header))
        return -1;

    const struct psf2_header* header = (const struct psf2_header*)buf;
    if (header->magic != PSF2_MAGIC || header->version != 0 ||
        header->headersize != sizeof(struct psf2_header))
        return -1;

    font->width = header->width;
    font->height = header->height;
    font->char_count = header->numglyph;
    font->char_size = header->bytesperglyph;
    font->data = buf + header->headersize;

    return 0;
}

NODISCARD static int load_psf(struct font* font, unsigned char* buf,
                              size_t buf_size) {
    int rc = load_psf1(font, buf, buf_size);
    if (rc >= 0)
        return rc;
    return load_psf2(font, buf, buf_size);
}

int main(void) {
    size_t buf_size = 1024;
    unsigned char* buf = NULL;
    size_t nread = 0;
    for (;;) {
        unsigned char* new_buf = realloc(buf, buf_size);
        if (!new_buf) {
            perror("realloc");
            return EXIT_FAILURE;
        }
        buf = new_buf;
        ssize_t n = read(STDIN_FILENO, buf + nread, buf_size - nread);
        if (n < 0) {
            perror("read");
            free(buf);
            return EXIT_FAILURE;
        }
        if (n == 0)
            break;
        nread += n;
        if (nread == buf_size)
            buf_size *= 2;
    }

    struct font font = {0};
    int rc = load_psf(&font, buf, nread);
    if (rc < 0) {
        dprintf(STDERR_FILENO, "Not a valid PSF font\n");
        free(buf);
        return EXIT_FAILURE;
    }
    if (font.width < 1 || font.height < 1) {
        dprintf(STDERR_FILENO, "Invalid font dimensions\n");
        free(buf);
        return EXIT_FAILURE;
    }

    unsigned char_width = 32 * DIV_CEIL(font.width, 8);
    size_t data_size =
        char_width * ((font.char_count < 128) ? 128 : font.char_count);
    unsigned char* data = malloc(data_size);
    if (!data) {
        perror("malloc");
        free(buf);
        return EXIT_FAILURE;
    }
    memset(data, 0, data_size);
    for (unsigned i = 0; i < font.char_count; ++i)
        memcpy(data + i * char_width, font.data + i * font.char_size,
               font.char_size);
    free(buf);

    struct console_font_op font_op = {
        .op = KD_FONT_OP_SET,
        .width = font.width,
        .height = font.height,
        .charcount = font.char_count,
        .data = data,
    };
    if (ioctl(STDOUT_FILENO, KDFONTOP, &font_op) < 0) {
        perror("ioctl");
        free(data);
        return EXIT_FAILURE;
    }

    free(data);
    return EXIT_SUCCESS;
}
