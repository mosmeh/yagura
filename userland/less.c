#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static void print_one_page(const char* buf, struct winsize winsize,
                           size_t height, size_t line) {
    const char* p = buf;

    // Skip to the start of the page
    for (size_t i = 0; i < line; ++i) {
        size_t j = 0;
        for (; j < winsize.ws_col; ++j) {
            if (!*p)
                goto out;
            if (*p++ == '\n')
                break;
        }
        if (j == winsize.ws_col && *p == '\n') {
            // The line is exactly the width of the terminal, so the newline
            // character does not contribute to the line count.
            ++p;
        }
    }

    // Print the page

    printf("\x1b[?25l" // Hide cursor
           "\x1b[1;1H" // Move cursor to top left
           "\x1b[2K"); // Clear the first line

    for (size_t i = 0; i < height; ++i) {
        size_t j = 0;
        for (; j < winsize.ws_col; ++j) {
            if (!*p)
                goto out;
            if (*p == '\n')
                break;
            putchar(*p++);
        }
        if (*p == '\n') {
            ++p;
            printf("\x1b[1B"   // Move down one line
                   "\x1b[G"    // Go to left end
                   "\x1b[2K"); // Clear the line
        }
    }

out:
    printf("\x1b[J"     // Clear the rest of the screen
           "\x1b[%d;1H" // Go to the last line
           "\x1b[?25h", // Show cursor
           winsize.ws_row);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        dprintf(STDERR_FILENO, "Usage: less FILE\n");
        return EXIT_FAILURE;
    }

    const char* filename = argv[1];
    struct stat st;
    int fd = -1;
    char* buf = NULL;
    int ret = EXIT_FAILURE;

    if (stat(filename, &st) < 0) {
        perror("stat");
        goto fail;
    }
    size_t num_bytes = st.st_size * sizeof(unsigned char);

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        goto fail;
    }
    buf = malloc(num_bytes + 1); // +1 for null terminator
    if (!buf) {
        perror("malloc");
        goto fail;
    }
    size_t total_nread = 0;
    while (total_nread < num_bytes) {
        ssize_t nread = read(fd, buf, num_bytes);
        if (nread < 0) {
            perror("read");
            goto fail;
        }
        total_nread += nread;
    }
    close(fd);
    fd = -1;
    buf[total_nread] = 0;

    struct winsize winsize;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) < 0) {
        winsize.ws_col = 80;
        winsize.ws_row = 25;
    }

    // Count the number of lines, wrapping at winsize.ws_col
    size_t num_lines = 0;
    size_t column = 0;
    for (const char* p = buf; *p; ++p) {
        if (*p == '\n' || column == winsize.ws_col) {
            ++num_lines;
            column = 0;
            continue;
        }
        ++column;
    }

    printf("\x1b[2J"); // Clear screen

    size_t page_height = winsize.ws_row - 1;
    ssize_t line = 0;
    print_one_page(buf, winsize, page_height, line);
    printf("\x1b[7m%s\x1b[0m", filename); // Print filename at the last line

    for (;;) {
        char c;
        ssize_t nread = read(STDIN_FILENO, &c, 1);
        if (nread < 0) {
            perror("read");
            goto fail;
        }
        if (nread == 0)
            break;

        switch (c) {
        case 'q':
            goto done;
        case 'e':
        case 'E' - '@': // ^E
        case 'j':
        case 'N' - '@': // ^N
        case '\n':
            ++line;
            break;
        case 'y':
        case 'Y' - '@': // ^Y
        case 'k':
        case 'K' - '@': // ^K
        case 'P' - '@': // ^P
            --line;
            break;
        case 'f':
        case 'F' - '@': // ^F
        case 'V' - '@': // ^V
        case ' ':
            line += page_height;
            break;
        case 'b':
        case 'B' - '@': // ^B
            line -= page_height;
            break;
        case 'd':
        case 'D' - '@': // ^D
            line += page_height / 2;
            break;
        case 'u':
        case 'U' - '@': // ^U
            line -= page_height / 2;
            break;
        case 'g':
        case '<':
            line = 0;
            break;
        case 'G':
        case '>':
            line = num_lines;
            break;
        }
        line = MAX(0, MIN(line, (ssize_t)num_lines - (ssize_t)page_height));
        print_one_page(buf, winsize, page_height, line);
    }

done:
    ret = EXIT_SUCCESS;
fail:
    free(buf);
    if (fd >= 0)
        close(fd);
    return ret;
}
