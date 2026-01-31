#include <common/string.h>
#include <common/strings.h>
#include <panic.h>
#include <stdlib.h>

int main(void) {
    ASSERT(strcmp("ABC", "ABC") == 0);
    ASSERT(strcasecmp("ABC", "abc") == 0);

    ASSERT(strcmp("ABC", "AB") > 0);
    ASSERT(strcasecmp("ABC", "ab") > 0);

    ASSERT(strcmp("ABA", "ABZ") < 0);
    ASSERT(strcasecmp("ABA", "abz") < 0);

    ASSERT(strcmp("ABJ", "ABC") > 0);
    ASSERT(strcasecmp("ABJ", "abc") > 0);

    ASSERT(strcmp("\x81", "A") > 0);
    ASSERT(strcasecmp("\x81", "a") > 0);

    ASSERT(strncmp("ABC", "AB", 3) > 0);
    ASSERT(strncasecmp("ABC", "ab", 3) > 0);

    ASSERT(strncmp("ABC", "AB", 2) == 0);
    ASSERT(strncasecmp("ABC", "ab", 2) == 0);

    return EXIT_SUCCESS;
}
