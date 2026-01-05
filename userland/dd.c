#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char* parse(const char* arg, const char* key) {
    size_t n = strlen(key);
    if (strncmp(arg, key, n) != 0 || arg[n] != '=' || arg[n + 1] == 0)
        return NULL;
    return arg + n + 1;
}

int main(int argc, char* argv[]) {
    int input_fd = STDIN_FILENO;
    int output_fd = STDOUT_FILENO;
    size_t block_size = 512;
    size_t count = 0;
    size_t seek = 0;
    size_t skip = 0;
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        const char* v;

        v = parse(arg, "if");
        if (v) {
            if (input_fd != STDIN_FILENO)
                close(input_fd);
            input_fd = open(v, O_RDONLY);
            if (input_fd < 0) {
                perror("open");
                return EXIT_FAILURE;
            }
            continue;
        }

        v = parse(arg, "of");
        if (v) {
            if (output_fd != STDOUT_FILENO)
                close(output_fd);
            output_fd = open(v, O_WRONLY | O_CREAT | O_TRUNC, 0);
            if (output_fd < 0) {
                perror("open");
                return 1;
            }
            continue;
        }

        v = parse(arg, "bs");
        if (v) {
            block_size = atoi(v);
            continue;
        }

        v = parse(arg, "count");
        if (v) {
            count = atoi(v);
            continue;
        }

        v = parse(arg, "seek");
        if (v) {
            seek = atoi(v);
            continue;
        }

        v = parse(arg, "skip");
        if (v) {
            skip = atoi(v);
            continue;
        }

        dprintf(STDERR_FILENO, "Usage: dd [if=file] [of=file] [bs=size] "
                               "[count=n] [seek=n] [skip=n]\n");
        return EXIT_FAILURE;
    }

    if (seek) {
        if (lseek(output_fd, seek * block_size, SEEK_SET) < 0) {
            perror("lseek");
            return EXIT_FAILURE;
        }
    }

    char* buf = malloc(block_size);
    if (!buf) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    size_t partial_records_in = 0;
    size_t full_records_in = 0;
    size_t partial_records_out = 0;
    size_t full_records_out = 0;
    size_t copied_bytes = 0;
    int ret = EXIT_FAILURE;
    for (;;) {
        ssize_t nread = read(input_fd, buf, block_size);
        if (nread < 0) {
            perror("read");
            goto fail;
        }
        if (nread == 0)
            break;
        if ((size_t)nread < block_size)
            ++partial_records_in;
        else
            ++full_records_in;
        if (partial_records_in + full_records_in <= skip)
            continue;

        ssize_t nwritten = write(output_fd, buf, nread);
        if (nwritten < 0) {
            perror("write");
            goto fail;
        }
        if (nwritten == 0)
            break;
        if ((size_t)nwritten < block_size)
            ++partial_records_out;
        else
            ++full_records_out;
        copied_bytes += nwritten;
        if (count && (full_records_out + partial_records_out) >= count)
            break;
    }

    dprintf(STDERR_FILENO,
            "%zu+%zu records in\n"
            "%zu+%zu records out\n"
            "%zu bytes copied\n",
            partial_records_in, full_records_in, partial_records_out,
            full_records_out, copied_bytes);

    ret = EXIT_SUCCESS;
fail:
    free(buf);
    return ret;
}
