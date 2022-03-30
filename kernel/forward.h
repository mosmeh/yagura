#pragma once

// multiboot.h
typedef struct multiboot_info multiboot_info_t;

// system.h
typedef struct registers registers;

// mem.h
typedef struct page_directory page_directory;
typedef struct page_table page_table;
typedef union page_table_entry page_table_entry;

// process.h
typedef struct process process;

// fs/fs.h
struct file;
typedef struct file_description file_description;

// socket.h
typedef struct unix_socket unix_socket;
