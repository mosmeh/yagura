#pragma once

#include <common/macros.h>
#include <kernel/api/sys/limits.h>

struct inode;

NODISCARD int copy_pathname_from_user(char dest[static PATH_MAX],
                                      const char* user_src);
NODISCARD int ensure_directory_is_empty(struct inode*);
