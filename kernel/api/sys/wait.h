#pragma once

#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#define WTERMSIG(status) ((status) & 0x7f)
#define WSTOPSIG(status) WEXITSTATUS(status)
#define WIFEXITED(status) (WTERMSIG(status) == 0)
#define WIFSIGNALED(status)                                                    \
    ((0 < WTERMSIG(status)) && (WTERMSIG(status) < 0x7f))
#define WIFSTOPPED(status) (((status) & 0xff) == 0x7f)

#define W_EXITCODE(ret, sig) ((ret) << 8 | (sig))
#define W_STOPCODE(sig) ((sig) << 8 | 0x7f)

#define WNOHANG 1   // Don't block waiting.
#define WUNTRACED 2 // Report status of stopped children.
