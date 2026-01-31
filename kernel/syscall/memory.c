#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/mman.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/api/sys/uio.h>
#include <kernel/fs/file.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

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
    if (prot & PROT_EXEC)
        flags |= VM_EXEC;
    return flags;
}

long sys_mmap_pgoff(void* addr, size_t length, int prot, int flags, int fd,
                    unsigned long pgoff) {
    if (length == 0)
        return -EINVAL;
    if (!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED))
        return -EINVAL;
    if ((flags & MAP_ANONYMOUS) && (flags & MAP_PRIVATE) &&
        (flags & MAP_SHARED))
        return -EINVAL;

    if (flags & MAP_FIXED) {
        if ((uintptr_t)addr % PAGE_SIZE != 0)
            return -EINVAL;
    } else if (addr) {
        addr = (void*)ROUND_DOWN((uintptr_t)addr, PAGE_SIZE);
    }

    struct vm_obj* obj FREE(vm_obj) = NULL;
    if (flags & MAP_ANONYMOUS) {
        obj = anon_create();
        if (IS_ERR(ASSERT(obj)))
            return PTR_ERR(obj);
    } else {
        struct file* file FREE(file) = files_ref_file(current->files, fd);
        if (IS_ERR(ASSERT(file)))
            return PTR_ERR(file);
        if (S_ISDIR(file->inode->mode))
            return -ENODEV;
        int rc = validate_file_prot(file, prot, flags);
        if (IS_ERR(rc))
            return rc;
        obj = file_mmap(file);
        if (IS_ERR(ASSERT(obj)))
            return PTR_ERR(obj);
    }

    struct vm* vm = current->vm;
    SCOPED_LOCK(vm, vm);

    size_t npages = DIV_CEIL(length, PAGE_SIZE);
    struct vm_region* region = (flags & MAP_FIXED)
                                   ? vm_alloc_at(vm, addr, npages)
                                   : vm_alloc(vm, npages);
    if (IS_ERR(ASSERT(region)))
        return PTR_ERR(region);

    unsigned vm_flags = prot_to_vm_flags(prot) | VM_USER;
    if (flags & MAP_SHARED)
        vm_flags |= VM_SHARED;
    ASSERT_OK(vm_region_set_flags(region, 0, npages, vm_flags, ~0));

    vm_region_set_obj(region, obj, pgoff);

    return (long)vm_region_to_virt(region);
}

struct mmap_arg_struct {
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long offset;
};

long sys_old_mmap(struct mmap_arg_struct* user_arg) {
    struct mmap_arg_struct arg;
    if (copy_from_user(&arg, user_arg, sizeof(struct mmap_arg_struct)))
        return -EFAULT;
    if (arg.offset % PAGE_SIZE)
        return -EINVAL;
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
    if (end < start) // Overflow
        return -ENOMEM;

    struct vm* vm = current->vm;
    SCOPED_LOCK(vm, vm);
    struct vm_region* region =
        vm_find_intersection(vm, addr, (void*)(end << PAGE_SHIFT));
    if (IS_ERR(region))
        return PTR_ERR(region);
    while (region && start < region->end) {
        struct vm_region* prev = vm_prev_region(region);
        size_t offset = MAX(start, region->start) - region->start;
        size_t npages = MIN(end, region->end) - region->start - offset;
        int ret = fn(region, offset, npages, ctx);
        if (IS_ERR(ret))
            return ret;
        region = prev;
    }
    return 0;
}

static int unmap(struct vm_region* region, size_t offset, size_t npages,
                 void* ctx) {
    (void)ctx;
    return vm_region_free(region, offset, npages);
}

long sys_munmap(void* addr, size_t length) {
    return for_each_overlapping_region(addr, length, unmap, NULL);
}

static int protect(struct vm_region* region, size_t offset, size_t npages,
                   void* ctx) {
    unsigned vm_flags = *(unsigned*)ctx;
    return vm_region_set_flags(region, offset, npages, vm_flags,
                               VM_READ | VM_WRITE | VM_EXEC);
}

long sys_mprotect(void* addr, size_t len, int prot) {
    unsigned vm_flags = prot_to_vm_flags(prot);
    return for_each_overlapping_region(addr, len, protect, &vm_flags);
}

static int sync(struct vm_region* region, size_t offset, size_t npages,
                void* ctx) {
    (void)ctx;
    struct vm_obj* obj = region->obj;
    if (!obj || obj->vm_ops != &inode_vm_ops)
        return 0;

    struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
    uint64_t byte_offset = ((uint64_t)region->offset + offset) << PAGE_SHIFT;
    uint64_t nbytes = (uint64_t)npages << PAGE_SHIFT;
    int ret = inode_sync(inode, byte_offset, nbytes);
    return ret;
}

long sys_msync(void* addr, size_t length, int flags) {
    if (flags & ~(MS_ASYNC | MS_SYNC | MS_INVALIDATE))
        return -EINVAL;
    if ((flags & MS_SYNC) && (flags & MS_ASYNC))
        return -EINVAL;
    if (!(flags & (MS_SYNC | MS_ASYNC)))
        return -EINVAL;
    return for_each_overlapping_region(addr, length, sync, NULL);
}

NODISCARD
static long process_vm_rw(pid_t pid, const struct iovec* user_local_iov,
                          unsigned long liovcnt,
                          const struct iovec* user_remote_iov,
                          unsigned long riovcnt, unsigned long flags,
                          bool write) {
    if (flags)
        return -EINVAL;
    if (liovcnt == 0 || riovcnt == 0)
        return 0;
    if (!is_user_range(user_local_iov, liovcnt * sizeof(struct iovec)) ||
        !is_user_range(user_remote_iov, riovcnt * sizeof(struct iovec)))
        return -EFAULT;

    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ESRCH;

    struct vm* vm = task->vm;
    SCOPED_LOCK(vm, vm);

    size_t total_copied = 0;
    unsigned long local_iov_index = 0;
    struct iovec local_iov = {0};
    unsigned long remote_iov_index = 0;
    struct iovec remote_iov = {0};
    while (local_iov_index < liovcnt && remote_iov_index < riovcnt) {
        if (local_iov.iov_len == 0) {
            if (copy_from_user(&local_iov, user_local_iov + local_iov_index,
                               sizeof(struct iovec)))
                return -EFAULT;
            if (local_iov.iov_len == 0) {
                ++local_iov_index;
                continue;
            }
            if (!is_user_range(local_iov.iov_base, local_iov.iov_len))
                return -EFAULT;
        }
        if (remote_iov.iov_len == 0) {
            if (copy_from_user(&remote_iov, user_remote_iov + remote_iov_index,
                               sizeof(struct iovec)))
                return -EFAULT;
            if (remote_iov.iov_len == 0) {
                ++remote_iov_index;
                continue;
            }
            if (!is_user_range(remote_iov.iov_base, remote_iov.iov_len))
                return -EFAULT;
        }

        struct page* page =
            vm_get_page(vm, remote_iov.iov_base, write ? VM_WRITE : VM_READ);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            return -EFAULT;

        size_t to_copy = MIN(local_iov.iov_len, remote_iov.iov_len);
        to_copy = MIN(to_copy, PAGE_SIZE);
        size_t page_offset = (uintptr_t)remote_iov.iov_base % PAGE_SIZE;
        if (page_offset)
            to_copy = MIN(to_copy, PAGE_SIZE - page_offset);

        char buf[PAGE_SIZE];
        if (write) {
            if (copy_from_user(buf, local_iov.iov_base, to_copy))
                return -EFAULT;
            page_copy_from_buffer(page, buf, page_offset, to_copy);
        } else {
            page_copy_to_buffer(page, buf, page_offset, to_copy);
            if (copy_to_user(local_iov.iov_base, buf, to_copy))
                return -EFAULT;
        }

        total_copied += to_copy;

        local_iov.iov_base = (unsigned char*)local_iov.iov_base + to_copy;
        local_iov.iov_len -= to_copy;
        if (local_iov.iov_len == 0)
            ++local_iov_index;

        remote_iov.iov_base = (unsigned char*)remote_iov.iov_base + to_copy;
        remote_iov.iov_len -= to_copy;
        if (remote_iov.iov_len == 0)
            ++remote_iov_index;
    }

    return total_copied;
}

long sys_process_vm_readv(pid_t pid, const struct iovec* user_local_iov,
                          unsigned long liovcnt,
                          const struct iovec* user_remote_iov,
                          unsigned long riovcnt, unsigned long flags) {
    return process_vm_rw(pid, user_local_iov, liovcnt, user_remote_iov, riovcnt,
                         flags, false);
}

long sys_process_vm_writev(pid_t pid, const struct iovec* user_local_iov,
                           unsigned long liovcnt,
                           const struct iovec* user_remote_iov,
                           unsigned long riovcnt, unsigned long flags) {
    return process_vm_rw(pid, user_local_iov, liovcnt, user_remote_iov, riovcnt,
                         flags, true);
}
