#pragma once

#include "fs/fs.h"
#include "memory/memory.h"
#include "system.h"
#include <stdnoreturn.h>

typedef struct process {
    pid_t id;
    uint32_t eip, esp, ebp, ebx, esi, edi;
    struct fpu_state fpu_state;

    page_directory* pd;
    uintptr_t stack_top;
    range_allocator vaddr_allocator;

    char* cwd;
    file_descriptor_table fd_table;

    bool (*should_unblock)(void*);
    void* blocker_data;

    size_t user_ticks;
    size_t kernel_ticks;

    struct process* next; // for ready_queue or blocked_processes
} process;

extern process* current;
extern const struct fpu_state initial_fpu_state;

void process_init(void);

process* process_create_kernel_process(void (*entry_point)(void));
pid_t process_spawn_kernel_process(void (*entry_point)(void));

pid_t process_generate_next_pid(void);
noreturn void process_exit(int status);

void process_tick(bool in_kernel);

// if fd < 0, allocates lowest-numbered file descriptor that was unused
int process_alloc_file_descriptor(int fd, file_description*);

int process_free_file_descriptor(int fd);
file_description* process_get_file_description(int fd);
