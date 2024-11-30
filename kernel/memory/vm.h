#pragma once

#include "memory.h"

struct vm_obj;

struct vm_ops {
    void (*destroy_obj)(struct vm_obj*);
    struct page* (*get_page)(struct vm_obj*, size_t offset,
                             uint32_t error_code);
};

struct vm_obj {
    const struct vm_ops* vm_ops;
    struct vm_region* shared_regions;
    struct mutex lock;
    atomic_size_t ref_count;
};

void vm_obj_ref(struct vm_obj*);
void vm_obj_unref(struct vm_obj*);

struct vm_obj* anon_create(void);
struct vm_obj* phys_create(uintptr_t phys_addr, size_t npages);

struct vm {
    size_t start; // Start virtual address / PAGE_SIZE (inclusive)
    size_t end;   // End virtual address / PAGE_SIZE (exclusive)
    struct page_directory* page_directory;
    struct vm_region* regions;
    struct mutex lock;
    atomic_size_t ref_count;
};

// Region may be read
#define VM_READ 0x1

// Region may be written
#define VM_WRITE 0x2

// Region may be accessed from userland
#define VM_USER 0x4

// vm_obj is shared with other regions
#define VM_SHARED 0x8

// Write-combining is enabled for the region
#define VM_WC 0x10

struct vm_region {
    struct vm* vm;
    size_t start;   // Start virtual address / PAGE_SIZE (inclusive)
    size_t end;     // End virtual address / PAGE_SIZE (exclusive)
    size_t offset;  // Offset into the obj (in pages)
    unsigned flags; // VM_*
    struct vm_obj* obj;
    struct page* private_pages;
    struct vm_region* prev;        // prev->end <= start
    struct vm_region* next;        // end <= next->start
    struct vm_region* shared_next; // obj == shared_next->obj
};

extern struct vm* kernel_vm;

struct vm* vm_create(void* start, void* end);
void vm_ref(struct vm*);
void vm_unref(struct vm*);

// Switches to the virtual memory space. Returns the previous vm.
struct vm* vm_enter(struct vm*);

// Clones the virtual memory space.
struct vm* vm_clone(struct vm*);

NODISCARD bool vm_handle_page_fault(void* virt_addr, uint32_t error_code);

// Finds the region that contains the given address.
// Returns NULL if no region contains the address.
struct vm_region* vm_find(const struct vm*, void* virt_addr);

// Find the region with the smallest address that intersects with the given
// address range.
// Returns NULL if no region intersects with the address range.
struct vm_region* vm_find_intersection(const struct vm*, void* virt_start_addr,
                                       void* virt_end_addr);

// Allocates a virtual memory region at arbitrary address.
NODISCARD struct vm_region* vm_alloc(struct vm*, size_t npages);

// Allocates a virtual memory region at a specific virtual address range.
NODISCARD struct vm_region* vm_alloc_at(struct vm*, void* virt_addr,
                                        size_t npages);

// Sets the vm_obj and offset into the vm_obj.
// Panics if the region already has a vm_obj.
void vm_region_set_obj(struct vm_region*, struct vm_obj*, size_t offset);

// Returns the start virtual address of the region.
void* vm_region_to_virt(const struct vm_region*);

// Resizes a virtual memory region.
NODISCARD int vm_region_resize(struct vm_region*, size_t new_npages);

// Sets the flags of a virtual memory region.
// mask is a bitmask that specifies which flags are changed.
// If only a part of the region is modified, the region is split.
NODISCARD int vm_region_set_flags(struct vm_region*, size_t offset,
                                  size_t npages, unsigned flags, unsigned mask);

// Frees a virtual memory region.
// If only a part of the region is freed, the region is shrunk or split.
NODISCARD int vm_region_free(struct vm_region*, size_t offset, size_t npages);

static inline uint16_t vm_flags_to_pte_flags(unsigned vm_flags) {
    uint16_t pte_flags = (vm_flags & VM_USER) ? PTE_USER : PTE_GLOBAL;
    if (vm_flags & VM_WRITE)
        pte_flags |= PTE_WRITE;
    if (vm_flags & VM_USER)
        pte_flags |= PTE_USER;
    if (vm_flags & VM_WC)
        pte_flags |= PTE_PAT;
    return pte_flags;
}
