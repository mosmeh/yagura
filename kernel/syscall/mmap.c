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

void* sys_mmap(const struct mmap_params* user_params) {
    struct mmap_params params;
    if (!copy_from_user(&params, user_params, sizeof(struct mmap_params)))
        return ERR_PTR(-EINVAL);

    if (params.length == 0 || params.offset < 0 ||
        (params.offset % PAGE_SIZE) ||
        !((params.flags & MAP_PRIVATE) ^ (params.flags & MAP_SHARED)))
        return ERR_PTR(-EINVAL);

    if (params.flags & MAP_FIXED)
        return ERR_PTR(-ENOTSUP);
    if ((params.flags & MAP_ANONYMOUS) && (params.offset != 0))
        return ERR_PTR(-ENOTSUP);

    int flags = VM_USER;
    if (params.prot & PROT_READ)
        flags |= VM_READ;
    if (params.prot & PROT_WRITE)
        flags |= VM_WRITE;
    if (params.flags & MAP_SHARED)
        flags |= VM_SHARED;

    if (params.flags & MAP_ANONYMOUS) {
        void* addr = vm_alloc(params.length, flags);
        if (IS_ERR(addr))
            return addr;
        memset(addr, 0, params.length);
        return addr;
    }

    struct file* file = process_get_file(params.fd);
    if (IS_ERR(file))
        return file;
    if (S_ISDIR(file->inode->mode))
        return ERR_PTR(-ENODEV);

    return file_mmap(file, params.length, params.offset, flags);
}

int sys_munmap(void* addr, size_t length) {
    if ((uintptr_t)addr % PAGE_SIZE || length == 0)
        return -EINVAL;
    int rc = vm_unmap(addr, length);
    if (rc == -ENOENT)
        return 0;
    return rc;
}
