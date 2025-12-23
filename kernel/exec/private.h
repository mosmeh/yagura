#pragma once

#include <common/macros.h>
#include <kernel/api/sys/limits.h>
#include <stddef.h>

struct exec_image {
    struct vm_obj* obj;
    unsigned char* data;
};

struct loader {
    char pathname[PATH_MAX];
    struct exec_image image;

    struct vm* vm;
    unsigned char* stack_base;
    unsigned char* stack_ptr;

    size_t argc, envc;
    void* arg_start;
    void* arg_end;
    void* env_start;
    void* env_end;

    void* entry_point;
};

NODISCARD int elf_load(struct loader*);
