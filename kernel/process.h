#pragma once

#include <kernel/fs/fs.h>
#include <stdnoreturn.h>

#define USER_STACK_BASE (KERNEL_VADDR - STACK_SIZE)
#define USER_STACK_TOP KERNEL_VADDR

typedef struct process {
    pid_t id;
    uint32_t esp, ebp, eip;
    uintptr_t pd_paddr;
    uintptr_t stack_top;
    uintptr_t heap_next_vaddr;
    file_descriptor_table fd_table;
    struct process* next; // queue
} process;

extern process* current;

void process_init(void);

pid_t process_get_pid(void);

void process_switch(void);

pid_t process_spawn_kernel_process(void (*entry_point)(void));
noreturn void process_exit(int status);

int process_enter_userland(void (*entry_point)(void));
pid_t process_userland_fork(registers*);

uintptr_t process_alloc_virtual_address_range(uintptr_t size);

int process_alloc_file_descriptor(fs_node*);
int process_free_file_descriptor(int fd);
file_description* process_get_file_description(int fd);
