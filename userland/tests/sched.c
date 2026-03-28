#include <panic.h>
#include <sched.h>
#include <stdlib.h>

int main(void) {
    ASSERT_OK(sched_yield());

    cpu_set_t mask;
    CPU_ZERO(&mask);
    ASSERT_OK(sched_getaffinity(0, sizeof(mask), &mask));
    ASSERT(CPU_COUNT(&mask) > 0);

    return EXIT_SUCCESS;
}
