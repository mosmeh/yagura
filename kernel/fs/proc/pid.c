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
    struct task* task = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    int ret = 0;
    char* buf = NULL;
    mutex_lock(&task->lock);

    size_t len = task->arg_end - task->arg_start;
    if (!len)
        goto done;

    buf = kmalloc(len);
    if (!buf) {
        ret = -ENOMEM;
        goto done;
    }

    if (copy_from_remote_vm(task->vm, buf, (void*)task->arg_start, len)) {
        ret = -EFAULT;
        goto done;
    }

    ret = vec_append(vec, buf, len);

done:
    kfree(buf);
    mutex_unlock(&task->lock);
    task_unref(task);
    return ret;
}

static int print_comm(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    mutex_lock(&task->lock);

    char comm[sizeof(task->comm)];
    strlcpy(comm, task->comm, sizeof(task->comm));

    mutex_unlock(&task->lock);

    return vec_printf(vec, "%s\n", comm);
}

static int print_cwd(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    mutex_lock(&task->lock);
    mutex_lock(&task->fs->lock);
    char* cwd FREE(kfree) = path_to_string(task->fs->cwd);
    mutex_unlock(&task->fs->lock);
    mutex_unlock(&task->lock);
    if (!cwd)
        return -ENOMEM;

    return vec_printf(vec, "%s", cwd);
}

static int print_environ(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);
    struct task* task = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    int ret = 0;
    char* buf = NULL;
    mutex_lock(&task->lock);

    size_t len = task->env_end - task->env_start;
    if (!len)
        goto done;

    buf = kmalloc(len);
    if (!buf) {
        ret = -ENOMEM;
        goto done;
    }

    if (copy_from_remote_vm(task->vm, buf, (void*)task->env_start, len)) {
        ret = -EFAULT;
        goto done;
    }

    ret = vec_append(vec, buf, len);

done:
    kfree(buf);
    mutex_unlock(&task->lock);
    task_unref(task);
    return ret;
}

static int print_maps(struct file* file, struct vec* vec) {
    pid_t pid = pid_from_ino(file->inode->ino);
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ENOENT;

    int ret = 0;
    mutex_lock(&task->lock);
    struct vm* vm = task->vm;
    mutex_lock(&vm->lock);
    for (struct vm_region* region = vm_first_region(vm); region;
         region = vm_next_region(region)) {
        ret = vec_printf(vec, "%08x-%08x %c%c%c\n", region->start, region->end,
                         region->flags & VM_READ ? 'r' : '-',
                         region->flags & VM_WRITE ? 'w' : '-',
                         region->flags & VM_SHARED ? 's' : 'p');
        if (IS_ERR(ret))
            break;
    }
    mutex_unlock(&vm->lock);
    mutex_unlock(&task->lock);
    return ret;
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
