#include "syscall.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/sys/mman.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/memory/memory.h>
#include <kernel/safe_string.h>
#include <kernel/task.h>

void* sys_mmap_pgoff(void* addr, size_t length, int prot, int flags, int fd,
                     unsigned long pgoff) {
    (void)addr;

    if (length == 0 || !((flags & MAP_PRIVATE) ^ (flags & MAP_SHARED)))
        return ERR_PTR(-EINVAL);

    if (flags & MAP_FIXED)
        return ERR_PTR(-ENOTSUP);
    if ((flags & MAP_ANONYMOUS) && pgoff)
        return ERR_PTR(-ENOTSUP);

    int vm_flags = VM_USER;
    if (prot & PROT_READ)
        vm_flags |= VM_READ;
    if (prot & PROT_WRITE)
        vm_flags |= VM_WRITE;
    if (flags & MAP_SHARED)
        vm_flags |= VM_SHARED;

    if (flags & MAP_ANONYMOUS) {
        void* mapped_addr = vm_alloc(length, vm_flags);
        if (IS_ERR(mapped_addr))
            return mapped_addr;
        memset(mapped_addr, 0, length);
        return mapped_addr;
    }

    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return file;
    if (S_ISDIR(file->inode->mode))
        return ERR_PTR(-ENODEV);

    return file_mmap(file, length, pgoff * PAGE_SIZE, vm_flags);
}

struct mmap_arg_struct {
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long offset;
};

void* sys_old_mmap(struct mmap_arg_struct* user_arg) {
    struct mmap_arg_struct arg;
    if (copy_from_user(&arg, user_arg, sizeof(struct mmap_arg_struct)))
        return ERR_PTR(-EFAULT);
    if (arg.offset % PAGE_SIZE)
        return ERR_PTR(-EINVAL);
    return sys_mmap_pgoff((void*)arg.addr, arg.len, arg.prot, arg.flags, arg.fd,
                          arg.offset / PAGE_SIZE);
}

int sys_munmap(void* addr, size_t length) {
    if ((uintptr_t)addr % PAGE_SIZE || length == 0)
        return -EINVAL;
    int rc = vm_unmap(addr, length);
    if (rc == -ENOENT)
        return 0;
    return rc;
}
