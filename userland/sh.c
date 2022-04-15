#include "stdlib.h"
#include "syscall.h"
#include <common/string.h>
#include <string.h>

static int read_cmd(char* out_cmd) {
    size_t len = 0;
    for (;;) {
        char c;
        ssize_t nread = read(0, &c, 1);
        if (nread < 0)
            return -1;
        if (nread == 0)
            continue;
        switch (c) {
        case '\r':
            out_cmd[len] = '\0';
            return 0;
        case '\b':
        case '\x7f': // ^H
            if (len == 0)
                continue;
            out_cmd[--len] = '\0';
            printf("\b \b");
            break;
        case 'U' - '@': // ^U
            memset(out_cmd, 0, len);
            for (; len > 0; --len)
                printf("\b \b");
            break;
        case '\t':
            break;
        case 'D' - '@': // ^D
            if (len == 0) {
                strcpy(out_cmd, "exit");
                return 0;
            }
            break;
        default:
            out_cmd[len++] = c;
            putchar(c);
            break;
        }
    }
}

static void parse_cmd(char* cmd, int* out_argc, char* out_argv[]) {
    static const char* sep = " \t";
    size_t i = 0;
    char* saved_ptr;
    for (char* part = strtok_r(cmd, sep, &saved_ptr); part;
         part = strtok_r(NULL, sep, &saved_ptr), ++i)
        out_argv[i] = part;
    out_argv[i] = NULL;
    *out_argc = i;
}

static int exec_cmd(int argc, char* const argv[], char* const envp[]) {
    const char* name = argv[0];

    if (!strcmp(name, "exit")) {
        printf("exit\n");
        exit(0);
    }
    if (!strcmp(name, "pwd")) {
        static char buf[1024];
        puts(getcwd(buf, 1024));
        return 0;
    }
    if (!strcmp(name, "cd")) {
        if (argc < 2) {
            const char* home = getenv("HOME");
            if (home)
                return chdir(home);
            return 0;
        }
        return chdir(argv[1]);
    }

    pid_t pid = fork();
    if (pid == 0) {
        if (execvpe(name, argv, envp) < 0) {
            perror("execvpe");
            abort();
        }
    }
    return waitpid(pid, NULL, 0);
}

int main(int argc, char* const argv[], char* const envp[]) {
    (void)argc;
    (void)argv;

    for (;;) {
        static char buf[1024];
        getcwd(buf, 1024);
        printf("\x1b[36m%s\x1b[m $ ", buf);

        static char cmd[1024];
        memset(cmd, 0, 1024);
        if (read_cmd(cmd) < 0) {
            perror("read_cmd");
            return EXIT_FAILURE;
        }
        putchar('\n');

        int argc;
        char* argv[1024];
        parse_cmd(cmd, &argc, argv);

        if (argc == 0)
            continue;

        if (exec_cmd(argc, argv, envp) < 0) {
            perror("exec_cmd");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
