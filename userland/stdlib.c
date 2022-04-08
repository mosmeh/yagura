#include "stdlib.h"
#include "syscall.h"
#include <common/extra.h>
#include <kernel/api/dirent.h>
#include <kernel/api/errno.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/mman.h>
#include <kernel/api/signum.h>
#include <kernel/api/syscall.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char* const argv[], char* const envp[]);

void _start(int argc, char* const argv[], char* const envp[]) {
    exit(main(argc, argv, envp));
}

noreturn void abort(void) { exit(128 + SIGABRT); }

noreturn void panic(const char* message, const char* file, size_t line) {
    dprintf(2, "%s at %s:%u\n", message, file, line);
    abort();
}

#define MALLOC_HEAP_SIZE 0x100000

static struct {
    bool initialized;
    uintptr_t heap_start;
    uintptr_t ptr;
    size_t num_allocs;
} malloc_ctx;

static void malloc_init_if_needed(void) {
    if (malloc_ctx.initialized)
        return;

    void* heap = mmap(NULL, MALLOC_HEAP_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    ASSERT(heap != MAP_FAILED);
    malloc_ctx.heap_start = malloc_ctx.ptr = (uintptr_t)heap;
    malloc_ctx.num_allocs = 0;
    malloc_ctx.initialized = true;
}

void* aligned_alloc(size_t alignment, size_t size) {
    if (size == 0)
        return NULL;

    malloc_init_if_needed();

    uintptr_t aligned_ptr = round_up(malloc_ctx.ptr, alignment);
    uintptr_t next_ptr = aligned_ptr + size;
    if (next_ptr > malloc_ctx.heap_start + MALLOC_HEAP_SIZE) {
        errno = ENOMEM;
        return NULL;
    }

    memset((void*)aligned_ptr, 0, size);

    malloc_ctx.ptr = next_ptr;
    ++malloc_ctx.num_allocs;

    return (void*)aligned_ptr;
}

void* malloc(size_t size) { return aligned_alloc(alignof(max_align_t), size); }

void free(void* ptr) {
    if (!ptr)
        return;

    ASSERT(malloc_ctx.initialized);
    ASSERT(malloc_ctx.num_allocs > 0);
    if (--malloc_ctx.num_allocs == 0)
        malloc_ctx.ptr = malloc_ctx.heap_start;
}

int putchar(int ch) {
    char c = ch;
    if (write(1, &c, 1) < 0)
        return -1;
    return ch;
}

int puts(const char* str) {
    int rc = write(1, str, strlen(str));
    if (rc < 0)
        return -1;
    if (write(1, "\n", 1) < 0)
        return -1;
    return rc + 1;
}

int printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vdprintf(1, format, args);
    va_end(args);
    return ret;
}

int dprintf(int fd, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vdprintf(fd, format, args);
    va_end(args);
    return ret;
}

int vdprintf(int fd, const char* format, va_list ap) {
    char buf[1024];
    int len = vsnprintf(buf, 1024, format, ap);
    return write(fd, buf, len);
}

int errno;

#define ERRNO_MSG(I, MSG) MSG,
const char* errno_msgs[EMAXERRNO] = {ENUMERATE_ERRNO(ERRNO_MSG)};
#undef ERRNO_MSG

char* strerror(int errnum) {
    if (0 <= errnum && errnum < EMAXERRNO)
        return (char*)errno_msgs[errnum];
    return "Unknown error";
}

void perror(const char* s) { dprintf(2, "%s: %s\n", s, strerror(errno)); }

unsigned int sleep(unsigned int seconds) {
    struct timespec req = {.tv_sec = seconds, .tv_nsec = 0};
    struct timespec rem;
    if (nanosleep(&req, &rem) < 0)
        return rem.tv_sec;
    return 0;
}

#define DIR_BUF_CAPACITY 1024

typedef struct DIR {
    int fd;
    unsigned char buf[DIR_BUF_CAPACITY];
    size_t buf_size;
    size_t buf_cursor;
} DIR;

DIR* opendir(const char* name) {
    DIR* dirp = malloc(sizeof(DIR));
    if (!dirp)
        return NULL;
    dirp->fd = open(name, O_RDONLY);
    if (dirp->fd < 0)
        return NULL;
    return dirp;
}

int closedir(DIR* dirp) { return close(dirp->fd); }

struct dirent* readdir(DIR* dirp) {
    if (dirp->buf_cursor >= dirp->buf_size) {
        ssize_t nwritten = getdents(dirp->fd, dirp->buf, DIR_BUF_CAPACITY);
        if (nwritten <= 0)
            return NULL;
        dirp->buf_size = nwritten;
        dirp->buf_cursor = 0;
    }
    struct dirent* dent = (struct dirent*)(dirp->buf + dirp->buf_cursor);
    dirp->buf_cursor += dent->record_len;
    return dent;
}
