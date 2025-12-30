#pragma once

#include <common/macros.h>
#include <kernel/api/sys/limits.h>
#include <stdbool.h>
#include <stddef.h>

struct exec_image {
    struct vm_obj* obj;
    unsigned char* data;
};

NODISCARD int exec_image_load(struct exec_image*, const char* pathname);
void exec_image_unload(struct exec_image*);

struct loader {
    char pathname[PATH_MAX];
    struct exec_image image;

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

NODISCARD int loader_push_string_from_kernel(struct loader*, const char* str);
NODISCARD int loader_push_string_from_user(struct loader*,
                                           const char* user_str);
void loader_pop_string(struct loader*);

NODISCARD int elf_load(struct loader*);
NODISCARD int shebang_load(struct loader*);
