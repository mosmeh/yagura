#pragma once

#include <common/extra.h>
#include <kernel/lock.h>

struct page_directory;
typedef struct multiboot_info multiboot_info_t;

void page_init(const multiboot_info_t*);
uintptr_t page_alloc(void);
void page_ref(uintptr_t phys_addr);
void page_unref(uintptr_t phys_addr);

// Page may be written
#define PTE_WRITE 0x2

// Page may be accessed from userland
#define PTE_USER 0x4

// Page Attribute Table bit
// Used to enable write-combining caching.
#define PTE_PAT 0x80

// Page is global (not flushed from TLB on context switch)
#define PTE_GLOBAL 0x100

// Flag to indicate that the page is shared between multiple processes
// The bit is unused by the hardware, so we can use it for our purposes.
#define PTE_SHARED 0x200

// kernel heap starts right after the quickmap page
#define KERNEL_HEAP_START (KERNEL_VIRT_ADDR + 1024 * PAGE_SIZE)

// last 4MiB is for recursive mapping
#define KERNEL_HEAP_END 0xffc00000

void page_table_init(void);
NODISCARD int page_table_map_anon(uintptr_t virt_addr, uintptr_t size,
                                  uint16_t flags);
NODISCARD int page_table_map_phys(uintptr_t virt_addr, uintptr_t phys_addr,
                                  uintptr_t size, uint16_t flags);
NODISCARD int page_table_shallow_copy(uintptr_t to_virt_addr,
                                      uintptr_t from_virt_addr, uintptr_t size,
                                      uint16_t new_flags);
void page_table_unmap(uintptr_t virt_addr, uintptr_t size);
void page_table_set_flags(uintptr_t virt_addr, uintptr_t size, uint16_t flags);

struct page_directory* page_directory_create(void);
struct page_directory* page_directory_clone_current(void);
void page_directory_destroy_current(void);
void page_directory_switch(struct page_directory* to);

struct slab_cache {
    mutex lock;
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
