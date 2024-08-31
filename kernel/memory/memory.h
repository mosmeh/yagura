#pragma once

#define PAGE_SIZE 4096

#define KERNEL_VIRT_ADDR 0xc0000000
#define KERNEL_PDE_IDX (KERNEL_VIRT_ADDR >> 22)

// Page is mapped
#define PTE_PRESENT 0x1

// Page may be written
#define PTE_WRITE 0x2

// Page may be accessed from userland
#define PTE_USER 0x4

// Page Attribute Table bit
// Used to enable write-combining caching.
#define PTE_PAT 0x80

// Page is global (not flushed from TLB on context switch)
#define PTE_GLOBAL 0x100

// Flag to indicate that the page is shared between multiple vm instances.
// The bit is unused by the hardware, so we can use it for our purposes.
#define PTE_SHARED 0x200

#ifndef ASM_FILE

#include <common/extra.h>
#include <kernel/lock.h>

extern struct page_directory* kernel_page_directory;

typedef struct multiboot_info multiboot_info_t;

static inline bool is_user_address(const void* addr) {
    return addr && (uintptr_t)addr < KERNEL_VIRT_ADDR;
}

static inline bool is_user_range(const void* addr, size_t size) {
    if (!is_user_address(addr))
        return false;
    uintptr_t end = (uintptr_t)addr + size;
    return (uintptr_t)addr <= end && end <= KERNEL_VIRT_ADDR;
}

static inline bool is_kernel_address(const void* addr) {
    return addr && (uintptr_t)addr >= KERNEL_VIRT_ADDR;
}

static inline bool is_kernel_range(const void* addr, size_t size) {
    return is_kernel_address(addr) && (uintptr_t)addr <= (uintptr_t)addr + size;
}

void memory_init(const multiboot_info_t*);

struct memory_stats {
    size_t total;
    size_t free;
};

void memory_get_stats(struct memory_stats* out_stats);

void* kmalloc(size_t);
void* kaligned_alloc(size_t alignment, size_t);
void* krealloc(void*, size_t new_size);
void kfree(void*);

char* kstrdup(const char*);
char* kstrndup(const char*, size_t n);

uintptr_t virt_to_phys(void*);

// Region may be read
#define VM_READ 0x1

// Region may be written
#define VM_WRITE 0x2

// Region may be accessed from userland
#define VM_USER 0x4

// Region is shared between multiple vm instances
#define VM_SHARED 0x8

// Write-combining is enabled for the region
#define VM_WC 0x10

struct vm {
    uintptr_t start;
    uintptr_t end;
    struct page_directory* page_directory;
    struct mutex lock;
    struct vm_region* regions;
    atomic_size_t ref_count;
};

struct vm_region {
    uintptr_t start;
    uintptr_t end;
    int flags;
    struct vm_region* prev;
    struct vm_region* next;
};

extern struct vm* kernel_vm;

struct vm* vm_create(void* start, void* end);
void vm_ref(struct vm*);
void vm_unref(struct vm*);

// Switches to the virtual memory space.
void vm_enter(struct vm*);

// Clones the current virtual memory space.
struct vm* vm_clone(void);

// Allocates a virtual memory region mapped to free physical pages.
void* vm_alloc(size_t, int flags);

// Allocates a virtual memory region at a specific virtual address range.
NODISCARD void* vm_alloc_at(void*, size_t, int flags);

// Allocates a virtual memory region mapped to a specific physical address
// range.
void* vm_phys_map(uintptr_t phys_addr, size_t, int flags);

// Allocates a virtual memory region that has the same mapping as the specified
// virtual memory range.
void* vm_virt_map(void*, size_t, int flags);

// Resizes a virtual memory region.
NODISCARD void* vm_resize(void*, size_t new_size);

// Changes the flags of a virtual memory region.
NODISCARD int vm_set_flags(void*, size_t, int flags);

// Unmaps a virtual memory region.
// If only a part of the region is unmapped, the region is shrunk or split.
NODISCARD int vm_unmap(void*, size_t);

// Frees a region of memory in the virtual memory space.
// Equivalent to vm_unmap with the start address and size of the region.
// Fails if the address is not the start of a region.
NODISCARD int vm_free(void*);

// Allocates free pages and maps them to the virtual address range.
NODISCARD int page_table_map_anon(uintptr_t virt_addr, uintptr_t size,
                                  uint16_t flags);

// Maps the physical address range to the virtual address range.
NODISCARD int page_table_map_phys(uintptr_t virt_addr, uintptr_t phys_addr,
                                  uintptr_t size, uint16_t flags);

// Copies the page table entries from one virtual address range to another.
NODISCARD int page_table_shallow_copy(uintptr_t to_virt_addr,
                                      uintptr_t from_virt_addr, uintptr_t size,
                                      uint16_t new_flags);

// Unmaps the virtual address range.
void page_table_unmap(uintptr_t virt_addr, uintptr_t size);

// Changes the page table flags for the virtual address range.
void page_table_set_flags(uintptr_t virt_addr, uintptr_t size, uint16_t flags);

#endif
