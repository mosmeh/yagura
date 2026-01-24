#pragma once

#include <kernel/api/sys/stat.h>
#include <time.h>

struct stat {
    dev_t st_dev;         /* ID of device containing file */
    ino_t st_ino;         /* Inode number */
    mode_t st_mode;       /* File type and mode */
    nlink_t st_nlink;     /* Number of hard links */
    uid_t st_uid;         /* User ID of owner */
    gid_t st_gid;         /* Group ID of owner */
    dev_t st_rdev;        /* Device ID (if special file) */
    off_t st_size;        /* Total size, in bytes */
    blksize_t st_blksize; /* Block size for filesystem I/O */
    blkcnt_t st_blocks;   /* Number of 512 B blocks allocated */

    struct timespec st_atim; /* Time of last access */
    struct timespec st_mtim; /* Time of last modification */
    struct timespec st_ctim; /* Time of last status change */
};

int stat(const char* pathname, struct stat* buf);
int lstat(const char* pathname, struct stat* buf);
int fstat(int fd, struct stat* buf);
int fstatat(int dirfd, const char* restrict pathname,
            struct stat* restrict statbuf, int flags);

int mkdir(const char* pathname, mode_t mode);
int mkdirat(int dirfd, const char* pathname, mode_t mode);

int mknod(const char* pathname, mode_t mode, dev_t dev);
int mknodat(int dirfd, const char* pathname, mode_t mode, dev_t dev);
int mkfifo(const char* pathname, mode_t mode);

int chmod(const char* pathname, mode_t mode);
int fchmod(int fd, mode_t mode);
int fchmodat(int dirfd, const char* pathname, mode_t mode, int flags);
