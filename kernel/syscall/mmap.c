#include <common/extra.h>
#include <kernel/api/err.h>
#include <kernel/api/mman.h>
#include <kernel/api/stat.h>
#include <kernel/api/syscall.h>
#include <kernel/boot_defs.h>
#include <kernel/mem.h>
#include <kernel/process.h>
#include <string.h>

uintptr_t sys_mmap(const mmap_params* params) {
    if (params->length == 0 || params->offset < 0 ||
        !((params->flags & MAP_PRIVATE) ^ (params->flags & MAP_SHARED)))
        return -EINVAL;

    if (params->addr || !(params->prot & PROT_READ) || params->offset != 0)
        return -ENOTSUP;

    size_t length = round_up(params->length, PAGE_SIZE);

    uintptr_t vaddr = process_alloc_virtual_addr_range(length);
    if (IS_ERR(vaddr))
        return vaddr;

    if (params->flags & MAP_ANONYMOUS) {
        if (params->flags & MAP_SHARED)
            return -ENOTSUP;

        int rc = mem_map_to_anonymous_region(vaddr, length,
                                             mem_prot_to_flags(params->prot));
        if (IS_ERR(rc))
            return rc;

        memset((void*)vaddr, 0, length);
        return vaddr;
    }

    if (params->flags & MAP_PRIVATE)
        return -ENOTSUP;

    file_description* desc = process_get_file_description(params->fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (S_ISDIR(desc->file->mode))
        return -ENODEV;

    return fs_mmap(desc, vaddr, length, params->prot, params->offset);
}
