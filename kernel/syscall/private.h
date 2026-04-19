#pragma once

#include <common/macros.h>

struct inode;
struct timespec;
struct timespec32;

NODISCARD int ensure_directory_is_empty(struct inode*);
struct path* path_from_dirfd(int dirfd);

NODISCARD int copy_timespec_from_user32(struct timespec* ts,
                                        const struct timespec32* user_ts32);
