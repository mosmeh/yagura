#pragma once

#include <sys/types.h>

extern const char* const sys_signame[];
extern const char* const sys_siglist[];

int kill(pid_t pid, int sig);
