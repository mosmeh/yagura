#pragma once

#include <kernel/api/sys/wait.h>
#include <sys/types.h>

pid_t waitpid(pid_t pid, int* wstatus, int options);
