#include "private.h"
#include <common/integer.h>
#include <common/stdio.h>
#include <common/stdlib.h>
#include <kernel/api/dirent.h>
#include <kernel/containers/vec.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/vfs.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

static int print_mounts(struct file* file, struct vec* vec) {
    (void)file;
    return vec_printf(vec, "self/mounts");
}

static int print_self(struct file* file, struct vec* vec) {
    (void)file;
    return vec_printf(vec, "%d", current->thread_group->tgid);
}

NODISCARD static int sprintf_ticks(struct vec* vec, unsigned long ticks) {
    unsigned long i = ticks / CLK_TCK;

    // Map [0, CLK_TCK) to [0, 100)
    unsigned long frac = (ticks % CLK_TCK) * 100 / CLK_TCK;

    return vec_printf(vec, "%lu.%02lu", i, frac);
}

static int print_uptime(struct file* file, struct vec* vec) {
    (void)file;

    int rc = sprintf_ticks(vec, uptime);
    if (IS_ERR(rc))
        return rc;
    rc = vec_append(vec, " ", 1);
    if (IS_ERR(rc))
        return rc;

    size_t idle_ticks = 0;
    for (size_t i = 0; i < num_cpus; ++i) {
        struct task* task = cpus[i]->idle_task;
        idle_ticks += task->kernel_ticks;
        ASSERT(task->user_ticks == 0);
    }
    rc = sprintf_ticks(vec, idle_ticks);
    if (IS_ERR(rc))
        return rc;

    return vec_append(vec, "\n", 1);
}

static const struct proc_entry entries[] = {
    {"cmdline", S_IFREG, proc_print_cmdline},
    {"cpuinfo", S_IFREG, proc_print_cpuinfo},
    {"filesystems", S_IFREG, proc_print_filesystems},
    {"kallsyms", S_IFREG, proc_print_kallsyms},
    {"loadavg", S_IFREG, proc_print_loadavg},
    {"meminfo", S_IFREG, proc_print_meminfo},
    {"mounts", S_IFLNK, print_mounts},
    {"self", S_IFLNK, print_self},
    {"slabinfo", S_IFREG, proc_print_slabinfo},
    {"uptime", S_IFREG, print_uptime},
    {"version", S_IFREG, proc_print_version},
};

struct inode* proc_root_lookup(struct inode* parent, const char* name) {
    if (str_is_uint(name)) {
        pid_t pid = atoi(name);
        struct task* task FREE(task) = task_find_by_tid(pid);
        if (!task)
            return ERR_PTR(-ENOENT);
        return proc_create_inode(parent->mount, pid << PROC_PID_INO_SHIFT,
                                 NULL);
    }
    return proc_lookup(parent, name, entries, ARRAY_SIZE(entries));
}

static struct tree_node* find_task_with_lower_bound(pid_t tid) {
    ASSERT(spinlock_is_locked_by_current(&tasks_lock));
    struct tree_node* node = tasks.root;
    struct tree_node* result = NULL;
    while (node) {
        struct task* task = CONTAINER_OF(node, struct task, tree_node);
        if (tid < task->tid) {
            result = node;
            node = node->left;
        } else if (tid > task->tid) {
            node = node->right;
        } else {
            return node;
        }
    }
    return result;
}

int proc_root_getdents(struct file* file, getdents_callback_fn callback,
                       void* ctx) {
    SCOPED_LOCK(file, file);
    if (file->offset < ARRAY_SIZE(entries)) {
        int rc =
            proc_getdents(file, callback, ctx, entries, ARRAY_SIZE(entries));
        if (IS_ERR(rc))
            return rc;
    }

    if (file->offset < ARRAY_SIZE(entries) ||
        ARRAY_SIZE(entries) + INT_MAX < file->offset)
        return 0;

    pid_t offset_tid = file->offset - ARRAY_SIZE(entries);

    pid_t tids[256];
    size_t ntids = 0;
    {
        SCOPED_LOCK(spinlock, &tasks_lock);
        struct tree_node* node = find_task_with_lower_bound(offset_tid);
        for (; node && ntids < ARRAY_SIZE(tids); node = tree_next(node)) {
            struct task* task = CONTAINER_OF(node, struct task, tree_node);
            tids[ntids++] = task->tid;
        }
    }

    for (size_t i = 0; i < ntids; ++i) {
        pid_t tid = tids[i];

        char name[16];
        ASSERT((size_t)snprintf(name, sizeof(name), "%d", tid) < sizeof(name));
        ino_t ino = tid << PROC_PID_INO_SHIFT;
        if (!callback(name, ino, DT_DIR, ctx))
            break;

        // +1 to resume after this entry on next call
        file->offset = ARRAY_SIZE(entries) + tid + 1;
    }

    return 0;
}
