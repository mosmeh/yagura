#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

static void usage(void) {
    dprintf(STDERR_FILENO, "Usage: uname [-asnrvm]\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char* const argv[]) {
    bool all = false;
    bool nodename = false;
    bool release = false;
    bool version = false;
    bool machine = false;
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (arg[0] != '-' || arg[1] == '\0' || arg[2] != '\0')
            usage();
        switch (arg[1]) {
        case 'a':
            all = true;
            break;
        case 's':
            break;
        case 'n':
            nodename = true;
            break;
        case 'r':
            release = true;
            break;
        case 'v':
            version = true;
            break;
        case 'm':
            machine = true;
            break;
        default:
            usage();
        }
    }

    struct utsname buf;
    if (uname(&buf) < 0) {
        perror("uname");
        return EXIT_FAILURE;
    }

    printf("%s ", buf.sysname);
    if (all || nodename)
        printf("%s ", buf.nodename);
    if (all || release)
        printf("%s ", buf.release);
    if (all || version)
        printf("%s ", buf.version);
    if (all || machine)
        printf("%s", buf.machine);
    puts("");

    return EXIT_SUCCESS;
}
