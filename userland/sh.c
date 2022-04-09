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
        switch (c) {
        case '\r':
            cmd[*len] = '\0';
            return 0;
        case '\b':
        case '\x7f': // ^H
            if (*len == 0)
                continue;
            --(*len);
            printf("\b \b");
            break;
        case 'U' - '@': // ^U
            for (; *len > 0; --(*len))
                printf("\b \b");
            break;
        default:
            cmd[(*len)++] = c;
            putchar(c);
            break;
        }
    }
}

static void parse_cmd(char* cmd, char* argv[]) {
    static const char* sep = " \t";
    size_t i = 0;
    char* saved_ptr;
    for (char* part = strtok_r(cmd, sep, &saved_ptr); part;
         part = strtok_r(NULL, sep, &saved_ptr), ++i)
        argv[i] = part;
    argv[i] = NULL;
}

static int exec_cmd(char* const argv[]) {
    if (!strcmp(argv[0], "exit")) {
        exit(0);
    }

    pid_t pid = fork();
    if (pid == 0) {
        char* envp[] = {NULL};
        if (execve(argv[0], argv, envp) < 0) {
            perror("execve");
            abort();
        }
    }
    return waitpid(pid, NULL, 0);
}

int main(void) {
    for (;;) {
        printf("$ ");
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
        parse_cmd(cmd, argv);

        if (exec_cmd(argv) < 0) {
            perror("exec_cmd");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
