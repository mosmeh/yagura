#pragma once

#include <common/macros.h>
#include <common/stdbool.h>
#include <common/stddef.h>
#include <kernel/api/sys/limits.h>

struct vm_obj* exec_open(const char* pathname);

struct loader {
    char pathname[PATH_MAX];
    struct vm_obj* vm_obj;

    struct vm* vm;
    unsigned char* stack_base;
    unsigned char* stack_ptr;

    char* execfn;

    size_t argc, envc;
    void* arg_start;
    void* arg_end;
    void* env_start;
    void* env_end;

    void* entry_point;

    bool commit;
};

NODISCARD int loader_open(struct loader*, const char* pathname);
NODISCARD int loader_push_string_from_kernel(struct loader*, const char* str);
NODISCARD int loader_push_string_from_user(struct loader*,
                                           const char* user_str);
NODISCARD int loader_pop_string(struct loader*);

NODISCARD int elf_load(struct loader*);
NODISCARD int shebang_load(struct loader*);
