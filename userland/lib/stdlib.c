#include "stdlib.h"
#include "errno.h"
#include "panic.h"
#include "signal.h"
#include "signum.h"
#include "string.h"
#include "sys/mman.h"
#include "unistd.h"
#include <extra.h>
#include <stdalign.h>

noreturn void abort(void) {
    kill(getpid(), SIGABRT);
    UNREACHABLE();
}

#define MALLOC_MAGIC 0xab4fde8d

struct malloc_header {
    uint32_t magic;
    size_t size;
    unsigned char data[];
};

static size_t page_size;

void* aligned_alloc(size_t alignment, size_t size) {
    if (size == 0)
        return NULL;

    if (!page_size)
        page_size = sysconf(_SC_PAGESIZE);

    ASSERT(alignment <= page_size);

    size_t data_offset =
        round_up(offsetof(struct malloc_header, data), alignment);
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

    void* ptr = (void*)((uintptr_t)addr + data_offset);
    memset(ptr, 0, size);
    return ptr;
}

void* malloc(size_t size) { return aligned_alloc(alignof(max_align_t), size); }

void free(void* ptr) {
    if (!ptr)
        return;
    ASSERT(page_size);
    uintptr_t addr = round_down((uintptr_t)ptr, page_size);
    if ((uintptr_t)ptr - addr < sizeof(struct malloc_header))
        addr -= page_size;
    struct malloc_header* header = (struct malloc_header*)addr;
    ASSERT(header->magic == MALLOC_MAGIC);
    ASSERT_OK(munmap((void*)header, header->size));
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
