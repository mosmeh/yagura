#include "private.h"
#include <common/integer.h>
#include <errno.h>
#include <panic.h>
#include <signal.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

noreturn void exit(int status) {
    SYSCALL1(exit_group, status);
    __builtin_unreachable();
}

noreturn void abort(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGABRT);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    (void)raise(SIGABRT);

    // If SIGABRT was caught, retry after removing the handler
    struct sigaction act = {.sa_handler = SIG_DFL};
    sigaction(SIGABRT, &act, NULL);
    (void)raise(SIGABRT);

    // If it's still not terminated, raise SIGKILL
    (void)raise(SIGKILL);
    __builtin_unreachable();
}

#define MALLOC_MAGIC 0xab4fde8d

struct malloc_header {
    uint32_t magic;
    size_t size;
    unsigned char data[];
};

void* aligned_alloc(size_t alignment, size_t size) {
    if (size == 0)
        return NULL;

    ASSERT(alignment <= getauxval(AT_PAGESZ));

    size_t data_offset =
        ROUND_UP(offsetof(struct malloc_header, data), alignment);
    size_t real_size = data_offset + size;
    void* addr = mmap(NULL, real_size, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (addr == MAP_FAILED) {
        errno = ENOMEM;
        return NULL;
    }

    struct malloc_header* header = (struct malloc_header*)addr;
    header->magic = MALLOC_MAGIC;
    header->size = real_size;

    return (void*)((uintptr_t)addr + data_offset);
}

void* malloc(size_t size) { return aligned_alloc(alignof(max_align_t), size); }

void* calloc(size_t num, size_t size) {
    size_t total_size = num * size;
    void* ptr = malloc(total_size);
    if (!ptr)
        return NULL;
    memset(ptr, 0, total_size);
    return ptr;
}

static struct malloc_header* header_from_ptr(void* ptr) {
    size_t page_size = getauxval(AT_PAGESZ);
    uintptr_t addr = ROUND_DOWN((uintptr_t)ptr, page_size);
    if ((uintptr_t)ptr - addr < sizeof(struct malloc_header))
        addr -= page_size;

    struct malloc_header* header = (struct malloc_header*)addr;
    ASSERT(header->magic == MALLOC_MAGIC);
    return header;
}

void* realloc(void* ptr, size_t new_size) {
    if (!ptr)
        return malloc(new_size);
    if (new_size == 0) {
        free(ptr);
        return NULL;
    }

    struct malloc_header* old_header = header_from_ptr(ptr);
    if (old_header->size >= new_size)
        return ptr;

    void* new_ptr = malloc(new_size);
    if (!new_ptr)
        return NULL;

    struct malloc_header* new_header = header_from_ptr(new_ptr);
    memcpy(new_header->data, old_header->data,
           old_header->size - offsetof(struct malloc_header, data));

    free(ptr);

    return new_ptr;
}

void free(void* ptr) {
    if (!ptr)
        return;
    struct malloc_header* header = header_from_ptr(ptr);
    ASSERT_OK(munmap(header, header->size));
}

char* getenv(const char* name) {
    for (char** env = environ; *env; ++env) {
        char* s = strchr(*env, '=');
        if (!s)
            continue;
        size_t len = s - *env;
        if (len > 0 && !strncmp(*env, name, len))
            return s + 1;
    }
    return NULL;
}

static int rand_state = 1;

int rand(void) {
    rand_state = ((rand_state * 1103515245U) + 12345U) & 0x7fffffff;
    return rand_state;
}

void srand(unsigned seed) { rand_state = seed == 0 ? 1 : seed; }
