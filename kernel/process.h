#pragma once

#include <kernel/fs/fs.h>
#include <stdnoreturn.h>

typedef struct process {
    pid_t id;
    uint32_t eip, esp, ebp, ebx, esi, edi;
    page_directory* pd;
    uintptr_t stack_top;
    uintptr_t heap_next_vaddr;
    file_descriptor_table fd_table;
    struct process* next; // queue
} process;

extern process* current;

void process_init(void);

pid_t process_spawn_kernel_process(void (*entry_point)(void));

void process_switch(void);
void process_enqueue(process*);

pid_t process_generate_next_pid(void);
pid_t process_get_pid(void);
noreturn void process_exit(int status);

uintptr_t process_alloc_virtual_addr_range(uintptr_t size);

int process_alloc_file_descriptor(struct file*);
int process_free_file_descriptor(int fd);
file_description* process_get_file_description(int fd);
