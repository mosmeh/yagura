#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int dump_file(int fd, bool canonical) {
    size_t offset = 0;
    for (;;) {
        uint8_t buf[16];
        ssize_t nread;
        size_t buf_len = 0;
        while (buf_len < sizeof(buf)) {
            nread = read(fd, (char*)buf + buf_len, sizeof(buf) - buf_len);
            if (nread < 0) {
                perror("read");
                return -1;
            }
            if (nread == 0)
                break;
            buf_len += nread;
        }
        if (buf_len == 0)
            break;

        printf("%08zx", offset);
        offset += 0x10;

        if (canonical) {
            putchar(' ');
            for (size_t i = 0; i < sizeof(buf); ++i) {
                if (i < buf_len)
                    printf(" %02x", buf[i]);
                else
                    printf("   ");
                if (i == 7)
                    putchar(' ');
            }
            printf("  |");
            for (size_t i = 0; i < buf_len; ++i)
                putchar(isprint(buf[i]) ? buf[i] : '.');
            printf("|\n");
        } else {
            for (size_t i = 0; i < buf_len; i += 2) {
                uint16_t word = buf[i];
                if (i + 1 < buf_len)
                    word |= buf[i + 1] << 8;
                printf(" %04x", word);
            }
            putchar('\n');
        }

        if (nread == 0)
            break;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    bool canonical = false;
    size_t num_files = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-C"))
            canonical = true;
        else
            ++num_files;
    }

    if (num_files == 0) {
        if (dump_file(STDIN_FILENO, canonical) < 0)
            return EXIT_FAILURE;
        return EXIT_SUCCESS;
    }

    int ret = EXIT_SUCCESS;
    for (int i = 1; i < argc; ++i) {
        const char* filename = argv[i];
        if (!strcmp(filename, "-C"))
            continue;
        int fd =
            strcmp(filename, "-") ? open(filename, O_RDONLY) : STDIN_FILENO;
        if (fd < 0) {
            perror("open");
            continue;
        }
        if (dump_file(fd, canonical) < 0)
            ret = EXIT_FAILURE;
        if (fd != STDIN_FILENO)
            close(fd);
    }
    return ret;
}
