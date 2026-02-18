#pragma once

#include <common/string.h>

char* strdup(const char* src);

char* strerror(int errnum);
const char* strerrorname_np(int errnum);
const char* strerrordesc_np(int errnum);

char* strsignal(int signum);
