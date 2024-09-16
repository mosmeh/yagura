#pragma once

#include <kernel/api/sys/wait.h>
#include <sys/types.h>

struct rusage;

pid_t waitpid(pid_t pid, int* wstatus, int options);
pid_t wait4(pid_t pid, int* wstatus, int options, struct rusage* rusage);
