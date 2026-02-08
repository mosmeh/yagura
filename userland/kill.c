#include <common/integer.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    dprintf(STDERR_FILENO, "Usage: kill [-SIGNUM] PID\n");
    exit(EXIT_FAILURE);
}

static int parse_signum(const char* s) {
    if (str_is_uint(s))
        return atoi(s);
    for (int i = 0; i < NSIG; ++i) {
        if (sys_signame[i] && !strcmp(s, sys_signame[i]))
            return i;
    }
    return -1;
}

int main(int argc, char* argv[]) {
    if (argc < 2)
        usage();

    pid_t pid = -1;
    int signum = SIGTERM;
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (arg[0] == '-') {
            signum = parse_signum(arg + 1);
            if (signum < 0 || signum >= NSIG)
                usage();
        } else if (str_is_uint(arg)) {
            pid = atoi(arg);
        } else {
            usage();
        }
    }
    if (pid < 0)
        usage();

    if (kill(pid, signum) < 0) {
        perror("kill");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
