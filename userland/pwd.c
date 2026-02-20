#include <stdio.h>
#include <stdlib.h>
#include <sys/limits.h>
#include <unistd.h>

static char buf[PATH_MAX + 1];

int main(void) {
    if (!getcwd(buf, sizeof(buf))) {
        perror("getcwd");
        return EXIT_FAILURE;
    }
    puts(buf);
    return EXIT_SUCCESS;
}
