#pragma once

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

enum {
    _SC_ARG_MAX,
    _SC_CLK_TCK,
    _SC_MONOTONIC_CLOCK,
    _SC_OPEN_MAX,
    _SC_PAGESIZE,
    _SC_PAGE_SIZE = _SC_PAGESIZE,
    _SC_SYMLOOP_MAX,
};
