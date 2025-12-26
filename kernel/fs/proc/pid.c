#include "private.h"
#include <common/string.h>
#include <kernel/api/sys/limits.h>
#include <kernel/containers/vec.h>
#include <kernel/fs/path.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>
#include <kernel/task.h>

static pid_t pid_from_ino(ino_t ino) {
    pid_t pid = ino >> PROC_PID_INO_SHIFT;
    ASSERT(pid > 0);
    return pid;
}

static int copy_from_remote_vm(struct vm* vm, void* dst, const void* user_src,
                               size_t size) {
    struct vm* current_vm = vm_enter(vm);
    int ret = copy_from_user(dst, user_src, size);
    vm_enter(current_vm);
    return ret;
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
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    char* cwd FREE(kfree) = NULL;
    {
        SCOPED_LOCK(task, task);
        SCOPED_LOCK(fs, task->fs);
        cwd = path_to_string(task->fs->cwd);
    }
    if (!cwd)
        return -ENOMEM;

    return vec_printf(vec, "%s", cwd);
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
        int ret = vec_printf(vec, "%08x-%08x %c%c%c\n", region->start,
                             region->end, region->flags & VM_READ ? 'r' : '-',
                             region->flags & VM_WRITE ? 'w' : '-',
                             region->flags & VM_SHARED ? 's' : 'p');
        if (IS_ERR(ret))
            return ret;
    }
    return 0;
}

static struct proc_entry entries[] = {
    {"cmdline", S_IFREG, print_cmdline}, {"comm", S_IFREG, print_comm},
    {"cwd", S_IFLNK, print_cwd},         {"environ", S_IFREG, print_environ},
    {"maps", S_IFREG, print_maps},
};

struct inode* proc_pid_lookup(struct inode* parent, const char* name) {
    return proc_lookup(parent, name, entries, ARRAY_SIZE(entries));
}

int proc_pid_getdents(struct file* file, getdents_callback_fn callback,
                      void* ctx) {
    return proc_getdents(file, callback, ctx, entries, ARRAY_SIZE(entries));
}
