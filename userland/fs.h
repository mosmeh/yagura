#pragma once

#include <stddef.h>
#include <sys/stat.h>

static inline void mode_to_string(mode_t mode, char out_buf[static 11]) {
    const char* type_chars = "?pc?d?b?-?l?s?w?";
    out_buf[0] = type_chars[(mode & S_IFMT) >> 12];

    const char* perm_chars = "rwxrwxrwx";
    for (size_t i = 0; i < 9; ++i)
        out_buf[i + 1] = (mode & (1 << (8 - i))) ? perm_chars[i] : '-';

    if (mode & S_ISUID)
        out_buf[3] = (mode & S_IXUSR) ? 's' : 'S';
    if (mode & S_ISGID)
        out_buf[6] = (mode & S_IXGRP) ? 's' : 'S';
    if (mode & S_ISVTX)
        out_buf[9] = (mode & S_IXOTH) ? 't' : 'T';

    out_buf[10] = '\0';
}
