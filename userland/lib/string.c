#include "string.h"
#include "errno.h"
#include "signal.h"
#include "stdio.h"
#include "stdlib.h"

char* strdup(const char* src) {
    size_t len = strlen(src);
    char* buf = malloc((len + 1) * sizeof(char));
    if (!buf)
        return NULL;

    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}

#define NAME(NAME, MSG) STRINGIFY(NAME),
#define MSG(NAME, MSG) MSG,
const char* const sys_errlist[] = {ENUMERATE_ERRNO(MSG)};
const char* const sys_signame[] = {ENUMERATE_SIGNALS(NAME)};
const char* const sys_siglist[] = {ENUMERATE_SIGNALS(MSG)};
#undef NAME
#undef MSG

char* strerror(int errnum) {
    if (0 <= errnum && errnum < EMAXERRNO)
        return (char*)sys_errlist[errnum];
    return "Unknown error";
}

char* strsignal(int signum) {
    if (0 <= signum && signum < NSIG)
        return (char*)sys_siglist[signum];
    return "Unknown signal";
}
