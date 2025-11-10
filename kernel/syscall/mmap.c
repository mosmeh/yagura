#include "syscall.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/mman.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/task.h>

NODISCARD static int validate_file_prot(struct file* file, int prot,
                                        int flags) {
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        // Writes to private mappings are allowed
        if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
            return -EACCES;
        break;
    case O_WRONLY:
        if (prot & PROT_READ)
            return -EACCES;
        break;
    case O_RDWR:
        break;
    default:
        UNREACHABLE();
    }
    return 0;
}

static unsigned prot_to_vm_flags(int prot) {
    unsigned flags = 0;
    if (prot & PROT_READ)
        flags |= VM_READ;
    if (prot & PROT_WRITE)
        flags |= VM_WRITE;
    return flags;
}

void* sys_mmap_pgoff(void* addr, size_t length, int prot, int flags, int fd,
                     unsigned long pgoff) {
    if (length == 0 || !((flags & MAP_PRIVATE) ^ (flags & MAP_SHARED)))
        return ERR_PTR(-EINVAL);

    struct vm_obj* obj;
    if (flags & MAP_ANONYMOUS) {
        obj = anon_create();
        if (IS_ERR(obj))
            return obj;
    } else {
        struct file* file = task_get_file(fd);
        if (IS_ERR(file))
            return file;
        if (S_ISDIR(file->inode->mode))
            return ERR_PTR(-ENODEV);
        int rc = validate_file_prot(file, prot, flags);
        if (IS_ERR(rc))
            return ERR_PTR(rc);
        obj = file_mmap(file);
        if (IS_ERR(obj))
            return obj;
    }

    struct vm* vm = current->vm;
    mutex_lock(&vm->lock);

    size_t npages = DIV_CEIL(length, PAGE_SIZE);
    struct vm_region* region = (flags & MAP_FIXED)
                                   ? vm_alloc_at(vm, addr, npages)
                                   : vm_alloc(vm, npages);
    if (IS_ERR(region)) {
        mutex_unlock(&vm->lock);
        vm_obj_unref(obj);
        return region;
    }

    unsigned vm_flags = prot_to_vm_flags(prot) | VM_USER;
    if (flags & MAP_SHARED)
        vm_flags |= VM_SHARED;
    ASSERT_OK(vm_region_set_flags(region, 0, npages, vm_flags, ~0));

    vm_region_set_obj(region, obj, pgoff);

    mutex_unlock(&vm->lock);
    return vm_region_to_virt(region);
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
                          arg.offset >> PAGE_SHIFT);
}

NODISCARD static int for_each_overlapping_region(
    void* addr, size_t length,
    int (*fn)(struct vm_region*, size_t offset, size_t npages, void* ctx),
    void* ctx) {
    if ((uintptr_t)addr % PAGE_SIZE || length == 0)
        return -EINVAL;

    size_t start = (uintptr_t)addr >> PAGE_SHIFT;
    size_t end = DIV_CEIL((uintptr_t)addr + length, PAGE_SIZE);

    struct vm* vm = current->vm;
    mutex_lock(&vm->lock);
    int ret = 0;
    struct vm_region* region =
        vm_find_intersection(vm, addr, (void*)(end << PAGE_SHIFT));
    while (region && region->start < end) {
        struct vm_region* next = region->next;
        size_t offset = MAX(start, region->start) - region->start;
        size_t npages = MIN(end, region->end) - region->start - offset;
        ret = fn(region, offset, npages, ctx);
        if (IS_ERR(ret))
            break;
        region = next;
    }
    mutex_unlock(&vm->lock);
    return ret;
}

static int unmap(struct vm_region* region, size_t offset, size_t npages,
                 void* ctx) {
    (void)ctx;
    return vm_region_free(region, offset, npages);
}

int sys_munmap(void* addr, size_t length) {
    return for_each_overlapping_region(addr, length, unmap, NULL);
}
