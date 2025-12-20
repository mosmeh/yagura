#pragma once

#include <kernel/memory/memory.h>
#include <kernel/resource.h>

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

struct vm_obj;

struct vm_ops {
    void (*destroy_obj)(struct vm_obj*);
    struct page* (*get_page)(struct vm_obj*, size_t index, bool write);
};

struct vm_obj {
    const struct vm_ops* vm_ops;
    struct vm_region* shared_regions; // Regions mapping this obj with VM_SHARED
    unsigned flags;                   // VM_* flags applied to all regions
    struct mutex lock;
    refcount_t refcount;
};

struct vm_obj* vm_obj_ref(struct vm_obj*);
void vm_obj_unref(struct vm_obj*);

DEFINE_FREE(vm_obj, struct vm_obj*, vm_obj_unref)

// Maps the given vm_obj into kernel virtual address space.
// Returns the virtual address.
void* vm_obj_map(struct vm_obj*, size_t offset, size_t npages, unsigned flags);

void vm_obj_unmap(void*);

// Invalidates shared mappings of the given vm_obj in all vms.
// The pages are removed from the page tables, causing page faults on the next
// access.
NODISCARD int vm_obj_invalidate_mappings(const struct vm_obj*, size_t offset,
                                         size_t npages);

struct vm_obj* anon_create(void);

struct vm_obj* phys_create(uintptr_t phys_addr, size_t npages);
void* phys_map(uintptr_t phys_addr, size_t size, unsigned vm_flags);
void phys_unmap(void*);

DEFINE_FREE(phys, void*, phys_unmap)

struct vm {
    size_t start; // Start virtual address in pages (inclusive)
    size_t end;   // End virtual address in pages (exclusive)
    struct page_directory* page_directory;
    struct tree regions;
    size_t cached_gap_start;
    size_t cached_gap_size;
    struct mutex lock;
    refcount_t refcount;
};

struct vm_region {
    struct vm* vm;
    size_t start;                  // Start virtual address in pages (inclusive)
    size_t end;                    // End virtual address in pages (exclusive)
    size_t offset;                 // Offset into the obj (in pages)
    unsigned flags;                // VM_*
    struct vm_obj* obj;            // Object backing this region
    struct tree private_pages;     // Pages referenced by MAP_PRIVATE regions
    struct tree_node tree_node;    // Node in vm->regions
    struct vm_region* shared_next; // obj == shared_next->obj
};

extern struct vm* kernel_vm;

struct vm* vm_create(void* start, void* end);
struct vm* vm_ref(struct vm*);
void vm_unref(struct vm*);

struct vm* vm_get_current(void);

// Switches to the virtual memory space. Returns the previous vm.
struct vm* vm_enter(struct vm*);

// Clones the virtual memory space.
struct vm* vm_clone(struct vm*);

NODISCARD bool vm_handle_page_fault(void* virt_addr, uint32_t error_code);

// Populates (prefaults) the page tables for the given virtual address range
// without the actual memory access.
NODISCARD int vm_populate(void* virt_start_addr, void* virt_end_addr,
                          bool write);

// Returns the first region in the vm.
struct vm_region* vm_first_region(const struct vm*);

// Iterates the regions in the vm.
struct vm_region* vm_next_region(const struct vm_region*);

// Iterates the regions in the vm in reverse order.
struct vm_region* vm_prev_region(const struct vm_region*);

// Finds the region that contains the given address.
// Returns NULL if no region contains the address.
struct vm_region* vm_find(const struct vm*, void* virt_addr);

// Find the region with the highest address that intersects with the given
// address range.
// Returns NULL if no region intersects with the address range.
struct vm_region* vm_find_intersection(const struct vm*, void* virt_start_addr,
                                       void* virt_end_addr);

// Allocates a virtual memory region at arbitrary address.
NODISCARD struct vm_region* vm_alloc(struct vm*, size_t npages);

// Allocates a virtual memory region at a specific virtual address range.
NODISCARD struct vm_region* vm_alloc_at(struct vm*, void* virt_addr,
                                        size_t npages);

// Sets the vm_obj as the backing object of the region.
// offset is the offset into the vm_obj (in pages).
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

// Invalidates mappings of the given region.
// The pages are removed from the page tables, causing page faults on the next
// access.
NODISCARD int vm_region_invalidate(const struct vm_region*, size_t offset,
                                   size_t npages);

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
