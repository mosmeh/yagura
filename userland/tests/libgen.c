#include <libgen.h>
#include <panic.h>
#include <stdlib.h>
#include <string.h>

static void test(const char* path, const char* dir, const char* base) {
    char dup_path[256];
    strlcpy(dup_path, path, sizeof(dup_path));
    ASSERT(strcmp(dirname(dup_path), dir) == 0);
    strlcpy(dup_path, path, sizeof(dup_path));
    ASSERT(strcmp(basename(dup_path), base) == 0);
}

int main(void) {
    test("/usr/lib", "/usr", "lib");
    test("/usr/", "/", "usr");
    test("usr", ".", "usr");
    test("/", "/", "/");
    test(".", ".", ".");
    test("..", ".", "..");
    return EXIT_SUCCESS;
}
