#pragma once

#include <common/macros.h>

struct inode;

NODISCARD int ensure_directory_is_empty(struct inode*);
struct path* path_from_dirfd(int dirfd);
