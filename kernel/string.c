#include "string.h"
#include "kmalloc.h"
#include <common/string.h>

char* kstrdup(const char* src) {
    char* buf = kmalloc(strlen(src) * sizeof(char));
    strcpy(buf, src);
    return buf;
}

char* kstrndup(const char* src, size_t n) {
    char* buf = kmalloc(strnlen(src, n) * sizeof(char));
    strncpy(buf, src, n);
    return buf;
}
