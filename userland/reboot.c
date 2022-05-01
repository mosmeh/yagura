#include <panic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <unistd.h>

int main(int argc, char* const argv[]) {
    ASSERT(argc >= 1);
    const char* filename = argv[0];
    if (!strcmp(filename, "reboot"))
        reboot(RB_AUTOBOOT);
    else if (!strcmp(filename, "halt"))
        reboot(RB_HALT);
    else if (!strcmp(filename, "poweroff"))
        reboot(RB_POWEROFF);
    return EXIT_FAILURE;
}
