#include "stdlib.h"
#include "syscall.h"
#include <common/string.h>
#include <string.h>

static int read_cmd(char* cmd, size_t* len) {
    *len = 0;
    for (;;) {
        char c;
        ssize_t nread = read(0, &c, 1);
        if (nread < 0)
            return -1;
        if (nread == 0)
            continue;
        if (c == '\r') {
            cmd[*len] = '\0';
            return 0;
        }
        if (c == '\b') {
            if (*len == 0)
                continue;
            --(*len);
            printf("\b \b");
        } else {
            cmd[(*len)++] = c;
            putchar(c);
        }
    }
}

static void parse_cmd(char* cmd, size_t len, char* argv[]) {
    str_replace_char(cmd, ' ', '\0');
    char* part = cmd;
    size_t i = 0;
    for (; part < cmd + len; ++i) {
        argv[i] = part;
        part += strlen(part) + 1;
    }
    argv[i] = NULL;
}

int main(void) {
    for (;;) {
        printf("> ");
        char cmd[1024];
        memset(cmd, 0, 1024);
        size_t len;
        if (read_cmd(cmd, &len) < 0) {
            perror("read_cmd");
            return EXIT_FAILURE;
        }
        putchar('\n');

        if (len == 0)
            continue;

        char* argv[1024];
        parse_cmd(cmd, len, argv);
        char* envp[] = {NULL};
        pid_t pid = fork();
        if (pid == 0) {
            if (execve(argv[0], argv, envp) < 0) {
                perror("execve");
                abort();
            }
        }
        if (waitpid(pid, NULL, 0) < 0)
            perror("waitpid");
    }
    return EXIT_SUCCESS;
}
