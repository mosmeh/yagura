#include "unistd.h"
#include "errno.h"
#include "panic.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/ioctl.h"
#include "time.h"

char** environ;

int execvpe(const char* file, char* const argv[], char* const envp[]) {
    if (strchr(file, '/'))
        return execve(file, argv, envp);

    const char* path = getenv("PATH");
    if (!path)
        path = "/bin";
    char* dup_path = strdup(path);
    if (!dup_path)
        return -1;

    int saved_errno = errno;

    static const char* sep = ":";
    char* saved_ptr;
    for (const char* part = strtok_r(dup_path, sep, &saved_ptr); part;
         part = strtok_r(NULL, sep, &saved_ptr)) {
        static char buf[1024];
        ASSERT(sprintf(buf, "%s/%s", part, file) > 0);
        int rc = execve(buf, argv, envp);
        ASSERT(rc < 0);
        if (errno != ENOENT)
            return -1;
        errno = saved_errno;
    }

    errno = ENOENT;
    return -1;
}

unsigned int sleep(unsigned int seconds) {
    struct timespec req = {.tv_sec = seconds, .tv_nsec = 0};
    struct timespec rem;
    if (nanosleep(&req, &rem) < 0)
        return rem.tv_sec;
    return 0;
}
pid_t tcgetpgrp(int fd) { return ioctl(fd, TIOCGPGRP, NULL); }

int tcsetpgrp(int fd, pid_t pgrp) { return ioctl(fd, TIOCSPGRP, &pgrp); }
