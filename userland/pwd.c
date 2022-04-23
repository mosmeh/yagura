#include "stdlib.h"
#include "syscall.h"

int main(void) {
    static char buf[1024];
    if (!getcwd(buf, 1024)) {
        perror("getcwd");
        return EXIT_FAILURE;
    }
    puts(buf);
    return EXIT_SUCCESS;
}
