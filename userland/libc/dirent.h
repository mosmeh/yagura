#pragma once

#include <common/stddef.h>
#include <kernel/api/dirent.h>
#include <sys/types.h>

typedef struct __DIR DIR;

struct dirent {
    ino_t d_ino; // Inode number
    off_t d_off;
    unsigned short d_reclen; // Length of this record
    unsigned char d_type;    // Type of file
    char d_name[256];        // Null-terminated filename
};

DIR* opendir(const char* name);
int closedir(DIR* dirp);
struct dirent* readdir(DIR* dirp);
