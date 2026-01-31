#include <libgen.h>
#include <panic.h>
#include <stdlib.h>
#include <string.h>

static void assert_basename(const char* path, const char* expected) {
    char dup_path[256];
    strlcpy(dup_path, path, sizeof(dup_path));
    char* result = basename(dup_path);
    ASSERT(strcmp(result, expected) == 0);
}

int main(void) {
    assert_basename("/usr/lib", "lib");
    assert_basename("/usr/", "usr");
    assert_basename("usr", "usr");
    assert_basename("/", "/");
    assert_basename(".", ".");
    assert_basename("..", "..");
    return EXIT_SUCCESS;
}
