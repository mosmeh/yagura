#pragma once

#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14

struct linux_dirent {
    unsigned long d_ino; // Inode number
    unsigned long d_off;
    unsigned short d_reclen; // Length of this linux_dirent
    char d_name[];           // Filename (null-terminated)
    // char pad;             // Zero padding byte
    // char d_type;          // File type
};
