#include <panic.h>
#include <stdlib.h>
#include <sys/resource.h>

int main(void) {
    struct rusage rusage = {
        .ru_utime = {.tv_sec = -1, .tv_usec = -1},
        .ru_stime = {.tv_sec = -1, .tv_usec = -1},
    };
    ASSERT_OK(getrusage(RUSAGE_SELF, &rusage));
    ASSERT(rusage.ru_utime.tv_sec >= 0);
    ASSERT(rusage.ru_utime.tv_usec >= 0);
    ASSERT(rusage.ru_stime.tv_sec >= 0);
    ASSERT(rusage.ru_stime.tv_usec >= 0);
    return EXIT_SUCCESS;
}
