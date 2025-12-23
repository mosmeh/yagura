#pragma once

#include <common/macros.h>

NODISCARD int execve_kernel(const char* pathname, const char* const* argv,
                            const char* const* envp);
NODISCARD int execve_user(const char* pathname, const char* const* user_argv,
                          const char* const* user_envp);
