#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* const argv[]) {
    if (argc != 2) {
        dprintf(STDERR_FILENO, "Usage: getty TTY\n");
        return EXIT_FAILURE;
    }

    const char* tty_name = argv[1];
    char tty_path[32];
    int len = snprintf(tty_path, sizeof(tty_path),
                       tty_name[0] == '/' ? "%s" : "/dev/%s", tty_name);
    if ((size_t)len >= sizeof(tty_path)) {
        dprintf(STDERR_FILENO, "TTY name too long\n");
        return EXIT_FAILURE;
    }

    close(STDIN_FILENO);
    int fd = open(tty_path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }
    if (dup2(fd, STDOUT_FILENO) < 0) {
        perror("dup2");
        return EXIT_FAILURE;
    }
    if (dup2(fd, STDERR_FILENO) < 0) {
        perror("dup2");
        return EXIT_FAILURE;
    }

    if (tcsetpgrp(STDIN_FILENO, getpid()) < 0) {
        perror("tcsetpgrp");
        return EXIT_FAILURE;
    }

    static char* const shell = "/bin/sh";
    execve(shell, (char* const[]){shell, NULL}, environ);
    perror("execve");

    return EXIT_FAILURE;
}
