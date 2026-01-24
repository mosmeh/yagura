#include <panic.h>
#include <stdlib.h>
#include <sys/random.h>

int main(void) {
    ASSERT_OK(getrandom(NULL, 0, 0));
    ASSERT_OK(getrandom((void*)1, 0, 0));

    char buf[16];
    ASSERT_OK(getrandom(buf, sizeof(buf), 0));

    return EXIT_SUCCESS;
}
