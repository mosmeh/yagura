#include <common/extra.h>
#include <kernel/api/err.h>
#include <kernel/api/sys/mman.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/boot_defs.h>
#include <kernel/memory/memory.h>
#include <kernel/process.h>
#include <string.h>

uintptr_t sys_mmap(const mmap_params* params) {
    if (params->length == 0 || params->offset < 0 ||
        (params->offset % PAGE_SIZE) ||
        !((params->flags & MAP_PRIVATE) ^ (params->flags & MAP_SHARED)))
        return -EINVAL;

    if ((params->flags & MAP_FIXED) || !(params->prot & PROT_READ))
        return -ENOTSUP;

    uintptr_t addr =
        range_allocator_alloc(&current->vaddr_allocator, params->length);
    if (IS_ERR(addr))
        return addr;

    uint16_t page_flags = PAGE_USER;
    if (params->prot & PROT_WRITE)
        page_flags |= PAGE_WRITE;
    if (params->flags & MAP_SHARED)
        page_flags |= PAGE_SHARED;

    if (params->flags & MAP_ANONYMOUS) {
        if (params->offset != 0)
            return -ENOTSUP;

        int rc = paging_map_to_free_pages(addr, params->length, page_flags);
        if (IS_ERR(rc))
            return rc;

        memset((void*)addr, 0, params->length);
        return addr;
    }

    file_description* desc = process_get_file_description(params->fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (S_ISDIR(desc->inode->mode))
        return -ENODEV;

    return file_description_mmap(desc, addr, params->length, params->offset,
                                 page_flags);
}

uintptr_t sys_munmap(void* addr, size_t length) {
    if ((uintptr_t)addr % PAGE_SIZE)
        return -EINVAL;
    paging_unmap((uintptr_t)addr, length);
    return range_allocator_free(&current->vaddr_allocator, (uintptr_t)addr,
                                length);
}
