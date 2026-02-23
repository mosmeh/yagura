#include <panic.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    ASSERT_ERRNO(setenv(NULL, "value", 1), EINVAL);
    ASSERT_ERRNO(setenv("", "value", 1), EINVAL);
    ASSERT_ERRNO(setenv("NAME=INVALID", "value", 1), EINVAL);
    ASSERT_ERRNO(unsetenv(NULL), EINVAL);
    ASSERT_ERRNO(unsetenv(""), EINVAL);
    ASSERT_ERRNO(unsetenv("NAME=INVALID"), EINVAL);

    ASSERT_OK(putenv(""));

    ASSERT_OK(setenv("TEST_VAR", "test_value", 1));
    ASSERT(!strcmp(getenv("TEST_VAR"), "test_value"));
    ASSERT_OK(setenv("TEST_VAR", "new_value", 0));
    ASSERT(!strcmp(getenv("TEST_VAR"), "test_value"));
    ASSERT_OK(setenv("TEST_VAR", "new_value", 1));
    ASSERT(!strcmp(getenv("TEST_VAR"), "new_value"));
    ASSERT_OK(unsetenv("TEST_VAR"));
    ASSERT(!getenv("TEST_VAR"));

    ASSERT_OK(putenv("TEST_VAR2=another_value"));
    ASSERT(!strcmp(getenv("TEST_VAR2"), "another_value"));
    ASSERT_OK(putenv("TEST_VAR2"));
    ASSERT(!getenv("TEST_VAR2"));

    ASSERT_OK(putenv("TEST_VAR3=third_value"));
    ASSERT(!strcmp(getenv("TEST_VAR3"), "third_value"));
    ASSERT_OK(unsetenv("TEST_VAR3"));
    ASSERT(!getenv("TEST_VAR3"));

    ASSERT_OK(setenv("TEST_VAR4", "fourth_value", 1));
    ASSERT(!strcmp(getenv("TEST_VAR4"), "fourth_value"));
    ASSERT_OK(clearenv());
    ASSERT(!getenv("TEST_VAR4"));
    ASSERT_OK(setenv("TEST_VAR4", "new_fourth_value", 0));
    ASSERT(!strcmp(getenv("TEST_VAR4"), "new_fourth_value"));

    return EXIT_SUCCESS;
}
