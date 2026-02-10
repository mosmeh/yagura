#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char* const argv[]) {
    if (argc < 2) {
        dprintf(STDERR_FILENO, "Usage: grep PATTERN [FILE]...\n");
        return EXIT_FAILURE;
    }

    const char* pattern = argv[1];

    for (int i = 2; i < argc; i++) {
        const char* filename = argv[i];

        struct stat st;
        if (stat(filename, &st) < 0) {
            perror("stat");
            return EXIT_FAILURE;
        }

        char* buf = malloc(st.st_size + 1); // +1 for null terminator
        if (!buf) {
            perror("malloc");
            return EXIT_FAILURE;
        }

        int fd = open(filename, O_RDONLY);
        if (fd < 0) {
            perror("open");
            goto done;
        }

        size_t buf_len = 0;
        ssize_t nread;
        while ((nread = read(fd, buf + buf_len, st.st_size - buf_len)) > 0)
            buf_len += nread;
        if (nread < 0) {
            perror("read");
            goto done;
        }
        close(fd);
        fd = -1;
        buf[buf_len] = 0;

        static const char* const sep = "\n";
        char* saved_ptr;
        for (char* line = strtok_r(buf, sep, &saved_ptr); line;
             line = strtok_r(NULL, sep, &saved_ptr)) {
            if (strstr(line, pattern)) {
                if (argc > 3)
                    printf("%s:%s\n", filename, line);
                else
                    puts(line);
            }
        }

    done:
        free(buf);
        if (fd >= 0)
            close(fd);
    }

    return EXIT_SUCCESS;
}
