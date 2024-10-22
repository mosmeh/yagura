#include "syscall.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/sys/mman.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/task.h>

static unsigned prot_to_vm_flags(int prot) {
    unsigned flags = VM_USER;
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
        obj = &file->inode->vm_obj;
        vm_obj_ref(obj);
    }

    struct vm* vm = current->vm;
    spinlock_lock(&vm->lock);

    size_t npages = DIV_CEIL(length, PAGE_SIZE);
    struct vm_region* region = (flags & MAP_FIXED)
                                   ? vm_alloc_at(vm, addr, npages)
                                   : vm_alloc(vm, npages);
    if (IS_ERR(region)) {
        spinlock_unlock(&vm->lock);
        vm_obj_unref(obj);
        return region;
    }

    unsigned vm_flags = prot_to_vm_flags(prot);
    if (flags & MAP_SHARED)
        vm_flags |= VM_SHARED;
    ASSERT_OK(vm_region_set_flags(region, 0, npages, vm_flags, ~0));

    vm_region_set_obj(region, obj, pgoff);

    spinlock_unlock(&vm->lock);
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
                          arg.offset / PAGE_SIZE);
}

NODISCARD static int for_each_overlapping_region(
    void* addr, size_t length,
    int (*fn)(struct vm_region*, size_t offset, size_t npages, void* ctx),
    void* ctx) {
    if ((uintptr_t)addr % PAGE_SIZE || length == 0)
        return -EINVAL;

    size_t start = (uintptr_t)addr / PAGE_SIZE;
    size_t end = DIV_CEIL((uintptr_t)addr + length, PAGE_SIZE);

    struct vm* vm = current->vm;
    spinlock_lock(&vm->lock);
    int ret = 0;
    struct vm_region* region = vm_find(vm, addr);
    while (region) {
        if (region->start >= end)
            break;
        struct vm_region* next = region->next;
        size_t npages = MIN(end, region->end) - region->start;
        ret = fn(region, start - region->start, npages, ctx);
        if (IS_ERR(ret))
            break;
        region = next;
    }
    spinlock_unlock(&vm->lock);
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

static int protect(struct vm_region* region, size_t offset, size_t npages,
                   void* ctx) {
    unsigned vm_flags = *(unsigned*)ctx;
    return vm_region_set_flags(region, offset, npages, vm_flags,
                               VM_READ | VM_WRITE);
}

int sys_mprotect(void* addr, size_t len, int prot) {
    unsigned vm_flags = prot_to_vm_flags(prot);
    return for_each_overlapping_region(addr, len, protect, &vm_flags);
}

static int sync(struct vm_region* region, size_t offset, size_t npages,
                void* ctx) {
    (void)ctx;
    (void)offset;
    (void)npages;
    struct vm_obj* obj = region->obj;
    if (!obj)
        return 0;
    struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
    // TODO: what if the vm_obj is not an inode?
    // TODO: sync only [offset, offset + npages)
    struct file* file = inode_open(inode, 0, 0);
    if (IS_ERR(file))
        return PTR_ERR(file);
    int ret = file_sync(file);
    file_unref(file);
    return ret;
}

int sys_msync(void* addr, size_t length, int flags) {
    if (flags & ~(MS_ASYNC | MS_SYNC | MS_INVALIDATE))
        return -EINVAL;
    if ((flags & MS_SYNC) && (flags & MS_ASYNC))
        return -EINVAL;
    if (flags & MS_INVALIDATE)
        UNIMPLEMENTED();
    return for_each_overlapping_region(addr, length, sync, NULL);
}
