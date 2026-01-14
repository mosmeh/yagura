#include "private.h"
#include <common/ctype.h>
#include <common/string.h>
#include <kernel/memory/memory.h>

#define SHEBANG_MAX_SIZE 255
STATIC_ASSERT(SHEBANG_MAX_SIZE < PAGE_SIZE); // Ensure trailing null

static char* strip_prefix(char* str, const char* last) {
    for (; str <= last; str++)
        if (!isblank(*str))
            return str;
    return NULL;
}

static char* find_terminator(char* str, const char* last) {
    for (; str <= last; str++)
        if (isblank(*str) || !*str)
            return str;
    return NULL;
}

int shebang_load(struct loader* loader) {
    // Parse `#!<interp> <arg>`

    char* data = (void*)loader->image.data;
    if (data[0] != '#' || data[1] != '!')
        return -ENOEXEC;

    char* end = strnchr(data, SHEBANG_MAX_SIZE, '\n');
    if (!end) {
        char* interp = strip_prefix(data + 2, data + SHEBANG_MAX_SIZE);
        if (!interp) {
            // Only blank characters after "#!"
            return -ENOEXEC;
        }
        if (!find_terminator(interp, data + SHEBANG_MAX_SIZE)) {
            // The interpreter path does not fit in SHEBANG_MAX_SIZE
            return -ENOEXEC;
        }
        // We have the full interpreter path within SHEBANG_MAX_SIZE
        end = data + SHEBANG_MAX_SIZE;
    }

    // Strip trailing blank characters
    while (isblank(*(end - 1)))
        --end;

    // Strip leading blank characters
    char* interp = strip_prefix(data + 2, end);
    if (!interp || interp >= end)
        return -ENOEXEC;

    char* sep = find_terminator(interp, end);
    const char* arg = NULL;
    if (sep && *sep) {
        // Skip blank characters between interpreter path and argument
        arg = strip_prefix(sep, end);
        *sep = 0; // Null-terminate the interpreter path
    }

    *end = 0; // Null-terminate the interpreter path or argument

    // Example:
    // $ cat script
    // #!/bin/program x y z
    // $ ./script a b

    // Initial stack layout:
    // argv[0] = "./script"
    // argv[1] = "a"
    // argv[2] = "b"

    // Replace the existing argv[0] with the pathname of the script
    int rc = loader_pop_string(loader);
    if (IS_ERR(rc))
        return rc;
    rc = loader_push_string_from_kernel(loader, loader->pathname);
    if (IS_ERR(rc))
        return rc;

    if (arg) {
        rc = loader_push_string_from_kernel(loader, arg);
        if (IS_ERR(rc))
            return rc;
        ++loader->argc;
    }

    rc = loader_push_string_from_kernel(loader, interp);
    if (IS_ERR(rc))
        return rc;
    ++loader->argc;

    loader->arg_start = loader->stack_ptr;

    // Final stack layout:
    // argv[0] = "/bin/program"
    // argv[1] = "x y z"
    // argv[2] = "./script"
    // argv[3] = "a"
    // argv[4] = "b"

    return exec_image_load(&loader->image, interp);
}
