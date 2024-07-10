#include "proc_private.h"
#include <common/string.h>
#include <kernel/api/sys/limits.h>
#include <kernel/fs/dentry.h>
#include <kernel/fs/path.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/safe_string.h>
#include <kernel/vec.h>

static bool copy_from_remote_vm(struct vm* vm, void* dst, const void* user_src,
                                size_t size) {
    struct vm* current_vm = current->vm;
    vm_enter(vm);
    bool ok = copy_from_user(dst, user_src, size);
    vm_enter(current_vm);
    return ok;
}

typedef struct {
    proc_item_inode item_inode;
    pid_t pid;
} proc_pid_item_inode;

static int populate_cmdline(struct file* file, struct vec* vec) {
    proc_pid_item_inode* node = (proc_pid_item_inode*)file->inode;
    struct process* process = process_find_by_pid(node->pid);
    if (!process)
        return -ENOENT;

    int ret = 0;
    char* buf = NULL;

    size_t len = process->arg_end - process->arg_start;
    if (!len)
        goto done;

    buf = kmalloc(len);
    if (!buf) {
        ret = -ENOMEM;
        goto done;
    }

    if (!copy_from_remote_vm(process->vm, buf, (void*)process->arg_start,
                             len)) {
        ret = -EFAULT;
        goto done;
    }

    ret = vec_append(vec, buf, len);

done:
    kfree(buf);
    process_unref(process);
    return ret;
}

static int populate_comm(struct file* file, struct vec* vec) {
    proc_pid_item_inode* node = (proc_pid_item_inode*)file->inode;
    struct process* process = process_find_by_pid(node->pid);
    if (!process)
        return -ENOENT;

    char comm[sizeof(process->comm)];
    strlcpy(comm, process->comm, sizeof(process->comm));

    process_unref(process);

    return vec_printf(vec, "%s\n", comm);
}

static int populate_cwd(struct file* file, struct vec* vec) {
    proc_pid_item_inode* node = (proc_pid_item_inode*)file->inode;
    struct process* process = process_find_by_pid(node->pid);
    if (!process)
        return -ENOENT;

    char* cwd = path_to_string(process->cwd);
    if (!cwd) {
        process_unref(process);
        return -ENOMEM;
    }

    int rc = vec_printf(vec, "%s", cwd);
    kfree(cwd);
    process_unref(process);
    return rc;
}

static int populate_environ(struct file* file, struct vec* vec) {
    proc_pid_item_inode* node = (proc_pid_item_inode*)file->inode;
    struct process* process = process_find_by_pid(node->pid);
    if (!process)
        return -ENOENT;

    int ret = 0;
    char* buf = NULL;

    size_t len = process->env_end - process->env_start;
    if (!len)
        goto done;

    buf = kmalloc(len);
    if (!buf) {
        ret = -ENOMEM;
        goto done;
    }

    if (!copy_from_remote_vm(process->vm, buf, (void*)process->env_start,
                             len)) {
        ret = -EFAULT;
        goto done;
    }

    ret = vec_append(vec, buf, len);

done:
    kfree(buf);
    process_unref(process);
    return ret;
}

static int populate_maps(struct file* file, struct vec* vec) {
    proc_pid_item_inode* node = (proc_pid_item_inode*)file->inode;
    struct process* process = process_find_by_pid(node->pid);
    if (!process)
        return -ENOENT;

    int ret = 0;
    struct vm* vm = process->vm;
    mutex_lock(&vm->lock);
    struct vm_region* region = vm->regions;
    while (region) {
        ret = vec_printf(vec, "%08x-%08x %c%c%c\n", region->start, region->end,
                         region->flags & VM_READ ? 'r' : '-',
                         region->flags & VM_WRITE ? 'w' : '-',
                         region->flags & VM_SHARED ? 's' : 'p');
        if (IS_ERR(ret))
            break;
        region = region->next;
    }
    mutex_unlock(&vm->lock);
    process_unref(process);
    return ret;
}

static int add_item(proc_dir_inode* parent, const proc_item_def* item_def,
                    pid_t pid) {
    proc_pid_item_inode* node = kmalloc(sizeof(proc_pid_item_inode));
    if (!node) {
        inode_unref((struct inode*)parent);
        return -ENOMEM;
    }
    *node = (proc_pid_item_inode){0};

    node->pid = pid;
    node->item_inode.populate = item_def->populate;

    struct inode* inode = &node->item_inode.inode;
    inode->dev = parent->inode.dev;
    inode->fops = &proc_item_fops;
    inode->mode = item_def->mode;
    inode->ref_count = 1;

    int rc = dentry_append(&parent->children, item_def->name, inode);
    inode_unref((struct inode*)parent);
    return rc;
}

static proc_item_def pid_items[] = {
    {"cmdline", S_IFREG, populate_cmdline},
    {"comm", S_IFREG, populate_comm},
    {"cwd", S_IFLNK, populate_cwd},
    {"environ", S_IFREG, populate_environ},
    {"maps", S_IFREG, populate_maps},
};

struct inode* proc_pid_dir_inode_create(proc_dir_inode* parent, pid_t pid) {
    struct process* process = process_find_by_pid(pid);
    if (!process)
        return ERR_PTR(-ENOENT);
    process_unref(process);

    proc_dir_inode* node = kmalloc(sizeof(proc_dir_inode));
    if (!node)
        return ERR_PTR(-ENOMEM);
    *node = (proc_dir_inode){0};

    static const struct file_ops fops = {
        .destroy_inode = proc_dir_destroy_inode,
        .lookup_child = proc_dir_lookup_child,
        .getdents = proc_dir_getdents,
    };
    struct inode* inode = &node->inode;
    inode->dev = parent->inode.dev;
    inode->fops = &fops;
    inode->mode = S_IFDIR;
    inode->ref_count = 1;

    for (size_t i = 0; i < ARRAY_SIZE(pid_items); ++i) {
        inode_ref(inode);
        int rc = add_item(node, pid_items + i, pid);
        if (IS_ERR(rc))
            return ERR_PTR(rc);
    }

    inode_unref((struct inode*)parent);
    return inode;
}
