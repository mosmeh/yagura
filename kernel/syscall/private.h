#pragma once

#include <common/macros.h>

struct inode;

NODISCARD int copy_pathname_from_user(char* dest, const char* user_src);
NODISCARD int ensure_directory_is_empty(struct inode*);
