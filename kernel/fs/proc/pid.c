#include "private.h"
#include <common/string.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/containers/vec.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/path.h>
#include <kernel/fs/vfs.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/safe_string.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>
#include <kernel/task/task.h>

static pid_t pid_from_ino(ino_t ino) {
    pid_t pid = ino >> PROC_PID_INO_SHIFT;
    ASSERT(pid > 0);
    return pid;
}

static int copy_from_remote_vm(struct vm* vm, void* dst, const void* user_src,
                               size_t size) {
    SCOPED_LOCK(vm, vm);
    size_t offset = 0;
    while (offset < size) {
        uintptr_t curr_addr = (uintptr_t)user_src + offset;
        struct page* page FREE(page) =
            vm_get_page(vm, (void*)curr_addr, VM_READ);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            return -EFAULT;
        size_t page_offset = curr_addr % PAGE_SIZE;
        size_t to_copy = MIN(PAGE_SIZE - page_offset, size - offset);
        page_copy_to_buffer(page, (unsigned char*)dst + offset, page_offset,
                            to_copy);
        offset += to_copy;
    }
    return 0;
}

static int print_cmdline(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    SCOPED_LOCK(task, task);

    size_t len = task->arg_end - task->arg_start;
    if (!len)
        return 0;

    char* buf FREE(kfree) = kmalloc(len);
    if (!buf)
        return -ENOMEM;

    if (copy_from_remote_vm(task->vm, buf, (void*)task->arg_start, len))
        return -EFAULT;

    return vec_append(vec, buf, len);
}

static int print_comm(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    char comm[sizeof(task->comm)];
    {
        SCOPED_LOCK(task, task);
        strlcpy(comm, task->comm, sizeof(task->comm));
    }

    return vec_printf(vec, "%s\n", comm);
}

static int print_cwd(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);

    char* cwd_str FREE(kfree) = NULL;
    {
        struct task* task FREE(task) = task_find_by_tid(pid);
        if (!task)
            return -ENOENT;

        struct path* cwd FREE(path) = NULL;
        {
            SCOPED_LOCK(task, task);
            SCOPED_LOCK(fs_env, task->fs_env);
            cwd = path_dup(task->fs_env->cwd);
        }
        if (IS_ERR(cwd))
            return PTR_ERR(cwd);

        struct path* root FREE(path) = NULL;
        {
            SCOPED_LOCK(fs_env, current->fs_env);
            root = path_dup(current->fs_env->root);
        }
        if (IS_ERR(root))
            return PTR_ERR(root);

        cwd_str = path_to_string(cwd, root);
        if (!cwd_str)
            return -ENOMEM;
    }

    return vec_printf(vec, "%s", cwd_str);
}

static int print_environ(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    SCOPED_LOCK(task, task);

    size_t len = task->env_end - task->env_start;
    if (!len)
        return 0;

    char* buf FREE(kfree) = kmalloc(len);
    if (!buf)
        return -ENOMEM;

    if (copy_from_remote_vm(task->vm, buf, (void*)task->env_start, len))
        return -EFAULT;

    return vec_append(vec, buf, len);
}

static int print_maps(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    SCOPED_LOCK(task, task);
    struct vm* vm = task->vm;
    SCOPED_LOCK(vm, vm);
    for (struct vm_region* region = vm_first_region(vm); region;
         region = vm_next_region(region)) {
        dev_t dev = 0;
        ino_t ino = 0;
        struct vm_obj* obj = region->obj;
        if (obj && obj->vm_ops == &inode_vm_ops) {
            struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
            struct kstat stat;
            if (IS_OK(inode_stat(inode, &stat))) {
                dev = stat.st_dev;
                ino = stat.st_ino;
            }
        }

        int ret =
            vec_printf(vec,
                       "%08zx-%08zx "
                       "%c%c%c%c "
                       "%08lx "
                       "%02x:%02x %lu\n",
                       region->start << PAGE_SHIFT, region->end << PAGE_SHIFT,
                       region->flags & VM_READ ? 'r' : '-',
                       region->flags & VM_WRITE ? 'w' : '-',
                       region->flags & VM_EXEC ? 'x' : '-',
                       region->flags & VM_SHARED ? 's' : 'p',
                       (unsigned long)region->offset << PAGE_SHIFT, major(dev),
                       minor(dev), ino);
        if (IS_ERR(ret))
            return ret;
    }
    return 0;
}

static int print_mounts(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;
    return proc_print_mounts(file, vec);
}

static const struct proc_entry entries[] = {
    {"cmdline", S_IFREG, print_cmdline}, {"comm", S_IFREG, print_comm},
    {"cwd", S_IFLNK, print_cwd},         {"environ", S_IFREG, print_environ},
    {"maps", S_IFREG, print_maps},       {"mounts", S_IFREG, print_mounts}};

struct inode* proc_pid_lookup(struct inode* parent, const char* name) {
    return proc_lookup(parent, name, entries, ARRAY_SIZE(entries));
}

int proc_pid_getdents(struct file* file, getdents_callback_fn callback,
                      void* ctx) {
    return proc_getdents(file, callback, ctx, entries, ARRAY_SIZE(entries));
}
