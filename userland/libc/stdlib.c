#include <common/integer.h>
#include <common/macros.h>
#include <errno.h>
#include <panic.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

void exit(int status) { _exit(status); }

void _Exit(int status) { _exit(status); }

void abort(void) {
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
    size_t alloc_size;
    size_t offset_to_data;
    unsigned char header_end[];
    // padding
    // data (at start of the struct + offset_to_data)
};

void* aligned_alloc(size_t alignment, size_t size) {
    if (alignment == 0 || !is_power_of_two(alignment) ||
        alignment % sizeof(void*) != 0) {
        errno = EINVAL;
        return NULL;
    }
    if (size == 0)
        return NULL;

    size_t page_size = getauxval(AT_PAGESZ);
    ASSERT(page_size % alignment == 0);

    size_t offset_to_data =
        ROUND_UP(offsetof(struct malloc_header, header_end), alignment);
    size_t alloc_size = ROUND_UP(offset_to_data + size, page_size);
    void* addr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (addr == MAP_FAILED) {
        errno = ENOMEM;
        return NULL;
    }

    struct malloc_header* header = (struct malloc_header*)addr;
    header->magic = MALLOC_MAGIC;
    header->alloc_size = alloc_size;
    header->offset_to_data = offset_to_data;

    return (void*)((uintptr_t)addr + offset_to_data);
}

void* malloc(size_t size) { return aligned_alloc(_Alignof(max_align_t), size); }

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
    size_t old_usable_size =
        old_header->alloc_size - old_header->offset_to_data;
    if (old_usable_size >= new_size)
        return ptr;

    void* new_ptr = malloc(new_size);
    if (!new_ptr)
        return NULL;
    memcpy(new_ptr, ptr, old_usable_size);
    free(ptr);
    return new_ptr;
}

void free(void* ptr) {
    if (!ptr)
        return;
    struct malloc_header* header = header_from_ptr(ptr);
    ASSERT_OK(munmap(header, header->alloc_size));
}

char* getenv(const char* name) {
    if (!environ)
        return NULL;
    size_t name_len = strlen(name);
    for (char** env = environ; *env; ++env) {
        char* s = strchr(*env, '=');
        if (!s)
            continue;
        size_t len = s - *env;
        if (len == name_len && !strncmp(*env, name, len))
            return s + 1;
    }
    return NULL;
}

static bool environ_is_malloced;
static char** malloced_vars;
static size_t malloced_vars_len;

NODISCARD static bool register_malloced_var(char* string) {
    for (size_t i = 0; i < malloced_vars_len; ++i) {
        if (malloced_vars[i]) {
            ASSERT(malloced_vars[i] != string);
            continue;
        }
        malloced_vars[i] = string;
        return true;
    }

    char** new_vars =
        realloc(malloced_vars, (malloced_vars_len + 1) * sizeof(char*));
    if (!new_vars)
        return false;
    malloced_vars = new_vars;
    malloced_vars[malloced_vars_len++] = string;
    return true;
}

static void free_var_if_needed(char* string) {
    for (size_t i = 0; i < malloced_vars_len; ++i) {
        if (malloced_vars[i] != string)
            continue;
        free(string);
        malloced_vars[i] = NULL;
        return;
    }
}

int putenv(char* string) {
    if (string[0] == '\0')
        return 0;

    char* eq = strchr(string, '=');
    if (!eq) {
        // glibc treats putenv("NAME") as unsetenv("NAME").
        return unsetenv(string);
    }

    size_t num_vars = 0;
    if (environ) {
        size_t name_len = eq - string;
        char** env = environ;
        for (; *env; ++env) {
            char* s = strchr(*env, '=');
            if (!s)
                continue;
            size_t len = s - *env;
            if (len != name_len || strncmp(*env, string, len) != 0)
                continue;
            if (*env == string)
                return 0;
            free_var_if_needed(*env);
            *env = string;
            return 0;
        }
        num_vars = env - environ;
    }

    size_t new_size = (num_vars + 2) * sizeof(char*);
    char** new_environ;
    if (environ_is_malloced) {
        new_environ = realloc(environ, new_size);
        if (!new_environ)
            return -1;
    } else {
        new_environ = malloc(new_size);
        if (!new_environ)
            return -1;
        if (environ)
            memcpy(new_environ, environ, num_vars * sizeof(char*));
        environ_is_malloced = true;
    }
    environ = new_environ;
    environ[num_vars] = string;
    environ[num_vars + 1] = NULL;

    return 0;
}

int setenv(const char* name, const char* value, int overwrite) {
    if (!name || name[0] == '\0' || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }

    if (!overwrite && getenv(name))
        return 0;

    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    char* string = malloc(name_len + 1 + value_len + 1);
    if (!string)
        return -1;
    memcpy(string, name, name_len);
    string[name_len] = '=';
    memcpy(string + name_len + 1, value, value_len);
    string[name_len + 1 + value_len] = '\0';

    if (!register_malloced_var(string)) {
        free(string);
        return -1;
    }

    if (putenv(string) < 0) {
        free_var_if_needed(string);
        return -1;
    }

    return 0;
}

int unsetenv(const char* name) {
    if (!name || name[0] == '\0' || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }

    if (!environ)
        return 0;

    size_t name_len = strlen(name);
    size_t i = 0;
    while (environ[i]) {
        char* s = strchr(environ[i], '=');
        if (!s) {
            ++i;
            continue;
        }
        size_t len = s - environ[i];
        if (len != name_len || strncmp(environ[i], name, len) != 0) {
            ++i;
            continue;
        }

        free_var_if_needed(environ[i]);

        // Shift remaining variables
        size_t j = i;
        for (; environ[j]; ++j)
            environ[j] = environ[j + 1];
        environ[j] = NULL;

        // Next variable shifted to the i-th position, so don't increment i
    }

    return 0;
}

int clearenv(void) {
    if (environ) {
        for (char** env = environ; *env; ++env)
            free_var_if_needed(*env);
    }
    free(malloced_vars);
    malloced_vars = NULL;
    malloced_vars_len = 0;

    if (environ_is_malloced) {
        free(environ);
        environ_is_malloced = false;
    }
    environ = NULL;

    return 0;
}

static int rand_state = 1;

int rand(void) {
    rand_state = ((rand_state * 1103515245U) + 12345U) & 0x7fffffff;
    return rand_state;
}

void srand(unsigned seed) { rand_state = seed == 0 ? 1 : seed; }
