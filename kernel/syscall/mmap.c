#include "syscall.h"
#include <common/extra.h>
#include <kernel/api/err.h>
#include <kernel/api/sys/mman.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/boot_defs.h>
#include <kernel/memory/memory.h>
#include <kernel/process.h>
#include <kernel/safe_string.h>
#include <string.h>

void* sys_mmap(const mmap_params* user_params) {
    mmap_params params;
    if (!copy_from_user(&params, user_params, sizeof(mmap_params)))
        return ERR_PTR(-EINVAL);

    if (params.length == 0 || params.offset < 0 ||
        (params.offset % PAGE_SIZE) ||
        !((params.flags & MAP_PRIVATE) ^ (params.flags & MAP_SHARED)))
        return ERR_PTR(-EINVAL);

    if ((params.flags & MAP_FIXED) || !(params.prot & PROT_READ))
        return ERR_PTR(-ENOTSUP);
    if ((params.flags & MAP_ANONYMOUS) && (params.offset != 0))
        return ERR_PTR(-ENOTSUP);

    uint16_t page_flags = PAGE_USER;
    if (params.prot & PROT_WRITE)
        page_flags |= PAGE_WRITE;
    if (params.flags & MAP_SHARED)
        page_flags |= PAGE_SHARED;

    if (params.flags & MAP_ANONYMOUS) {
        uintptr_t addr =
            range_allocator_alloc(&current->vaddr_allocator, params.length);
        if (IS_ERR(addr))
            return ERR_PTR(addr);

        int rc = paging_map_to_free_pages(addr, params.length, page_flags);
        if (IS_ERR(rc))
            return ERR_PTR(rc);

        memset((void*)addr, 0, params.length);
        return (void*)addr;
    }

    file_description* desc = process_get_file_description(params.fd);
    if (IS_ERR(desc))
        return desc;
    if (S_ISDIR(desc->inode->mode))
        return ERR_PTR(-ENODEV);

    uintptr_t addr =
        range_allocator_alloc(&current->vaddr_allocator, params.length);
    if (IS_ERR(addr))
        return ERR_PTR(addr);

    int rc = file_description_mmap(desc, addr, params.length, params.offset,
                                   page_flags);
    if (IS_ERR(rc))
        return ERR_PTR(rc);
    return (void*)addr;
}

int sys_munmap(void* addr, size_t length) {
    if ((uintptr_t)addr % PAGE_SIZE || length == 0)
        return -EINVAL;
    paging_user_unmap((uintptr_t)addr, length);
    int rc = range_allocator_free(&current->vaddr_allocator, (uintptr_t)addr,
                                  length);
    (void)rc;
    return 0;
}
