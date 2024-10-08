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

static uint32_t prot_to_vm_flags(int prot) {
    uint32_t flags = VM_USER;
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

    struct vobj* vobj;
    if (flags & MAP_ANONYMOUS) {
        vobj = anon_create();
        if (IS_ERR(vobj))
            return vobj;
    } else {
        struct file* file = task_get_file(fd);
        if (IS_ERR(file))
            return file;
        if (S_ISDIR(file->inode->mode))
            return ERR_PTR(-ENODEV);
        vobj = &file->vobj;
        vobj_ref(vobj);
    }

    struct vm* vm = current->vm;
    spinlock_lock(&vm->lock);

    size_t npages = DIV_CEIL(length, PAGE_SIZE);
    struct vm_region* region = (flags & MAP_FIXED)
                                   ? vm_alloc_at(vm, addr, npages)
                                   : vm_alloc(vm, npages);
    if (IS_ERR(region)) {
        spinlock_unlock(&vm->lock);
        vobj_unref(vobj);
        return region;
    }

    region->flags = prot_to_vm_flags(prot);
    if (flags & MAP_SHARED)
        region->flags |= VM_SHARED;

    region->offset = pgoff;
    vm_region_set_vobj(region, vobj);

    spinlock_unlock(&vm->lock);

    return (void*)(region->start * PAGE_SIZE);
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

static int for_each_overlapping_region(struct vm* vm, void* addr, size_t length,
                                       int (*fn)(struct vm_region*,
                                                 size_t offset, size_t npages,
                                                 void* ctx),
                                       void* ctx) {
    if ((uintptr_t)addr % PAGE_SIZE || length == 0)
        return -EINVAL;

    size_t start = (uintptr_t)addr / PAGE_SIZE;
    size_t end = DIV_CEIL((uintptr_t)addr + length, PAGE_SIZE);

    spinlock_lock(&vm->lock);
    int ret = 0;
    struct vm_region* region = vm_find(vm, addr);
    for (; region; region = region->next) {
        if (region->start >= end)
            break;
        ret = fn(region, start - region->start, end - region->start, ctx);
        if (IS_ERR(ret))
            break;
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
    return for_each_overlapping_region(current->vm, addr, length, unmap, NULL);
}

static int protect(struct vm_region* region, size_t offset, size_t npages,
                   void* ctx) {
    uint32_t vm_flags = *(uint32_t*)ctx;
    return vm_region_set_flags(region, offset, npages, vm_flags,
                               VM_READ | VM_WRITE);
}

int sys_mprotect(void* addr, size_t len, int prot) {
    uint32_t vm_flags = prot_to_vm_flags(prot);
    return for_each_overlapping_region(current->vm, addr, len, protect,
                                       &vm_flags);
}
