#pragma once

#include "memory.h"
#include <common/extra.h>
#include <kernel/lock.h>
#include <stdalign.h>

struct page_directory;
typedef struct multiboot_info multiboot_info_t;

typedef union {
    struct {
        bool present : 1;
        bool write : 1;
        bool user : 1;
        bool write_through : 1;
        bool cache_disable : 1;
        bool accessed : 1;
        bool ignored1 : 1;
        bool page_size : 1;
        uint8_t ignored2 : 4;
        uint32_t page_table_addr : 20;
    };
    uint32_t raw;
} __attribute__((packed)) page_directory_entry;

struct page_directory {
    alignas(PAGE_SIZE) page_directory_entry entries[1024];
};

void page_init(const multiboot_info_t*);
uintptr_t page_alloc(void);
void page_ref(uintptr_t phys_addr);
void page_unref(uintptr_t phys_addr);

// kernel heap starts right after the quickmap page
#define KERNEL_HEAP_START (KERNEL_VIRT_ADDR + 1024 * PAGE_SIZE)

// last 4MiB is for recursive mapping
#define KERNEL_HEAP_END 0xffc00000

void page_table_init(void);

struct page_directory* page_directory_create(void);
struct page_directory* page_directory_clone_current(void);
void page_directory_destroy_current(void);
void page_directory_switch(struct page_directory* to);

struct slab_cache {
    struct mutex lock;
    size_t obj_size;
    struct slab_obj* free_list;
};

void slab_cache_init(struct slab_cache*, size_t obj_size);
void* slab_cache_alloc(struct slab_cache*);
void slab_cache_free(struct slab_cache*, void*);

#define VM_RW (VM_READ | VM_WRITE)

struct vm;

void vm_init(void);

// Finds the region that contains the given address.
// Returns NULL if no region contains the address.
struct vm_region* vm_find_region(struct vm*, void* virt_addr);

// Finds a gap in the address space that can fit a region of the given size.
// Returns the region before the gap, or NULL if the vm is empty.
// If virt_addr is not NULL, the address of the gap is stored in it.
struct vm_region* vm_find_gap(struct vm*, size_t, uintptr_t* virt_addr);

// Inserts a region after the cursor. If the cursor is NULL, insert at the head.
void vm_insert_region_after(struct vm*, struct vm_region* cursor,
                            struct vm_region* inserted);

// Removes a region from the vm's region list.
void vm_remove_region(struct vm*, struct vm_region*);
