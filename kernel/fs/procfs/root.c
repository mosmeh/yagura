#include "procfs_private.h"
#include <common/stdio.h>
#include <common/stdlib.h>
#include <kernel/api/dirent.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/dentry.h>
#include <kernel/growable_buf.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/system.h>
#include <kernel/time.h>

static int populate_cmdline(file_description* desc, growable_buf* buf) {
    (void)desc;
    return growable_buf_printf(buf, "%s\n", cmdline_get_raw());
}

static int populate_kallsyms(file_description* desc, growable_buf* buf) {
    (void)desc;
    const struct symbol* symbol = NULL;
    while ((symbol = ksyms_next(symbol))) {
        if (growable_buf_printf(buf, "%08x %c %s\n", symbol->addr, symbol->type,
                                symbol->name) < 0)
            return -ENOMEM;
    }
    return 0;
}

static int populate_meminfo(file_description* desc, growable_buf* buf) {
    (void)desc;
    struct physical_memory_info memory_info;
    page_allocator_get_info(&memory_info);

    return growable_buf_printf(buf,
                               "MemTotal: %8u kB\n"
                               "MemFree:  %8u kB\n",
                               memory_info.total, memory_info.free);
}

static int populate_uptime(file_description* desc, growable_buf* buf) {
    (void)desc;
    return growable_buf_printf(buf, "%u\n", uptime / CLK_TCK);
}

static int populate_version(file_description* desc, growable_buf* buf) {
    (void)desc;
    return growable_buf_printf(buf, "%s version %s %s\n", utsname()->sysname,
                               utsname()->release, utsname()->version);
}

static procfs_item_def root_items[] = {{"cmdline", populate_cmdline},
                                       {"kallsyms", populate_kallsyms},
                                       {"meminfo", populate_meminfo},
                                       {"uptime", populate_uptime},
                                       {"version", populate_version}};
#define NUM_ITEMS ARRAY_SIZE(root_items)

static struct inode* procfs_root_lookup_child(struct inode* inode,
                                              const char* name) {
    if (str_is_uint(name)) {
        pid_t pid = atoi(name);
        return procfs_pid_dir_inode_create((procfs_dir_inode*)inode, pid);
    }
    return procfs_dir_lookup_child(inode, name);
}

static int procfs_root_getdents(file_description* desc,
                                getdents_callback_fn callback, void* ctx) {
    procfs_dir_inode* node = (procfs_dir_inode*)desc->inode;

    mutex_lock(&desc->offset_lock);
    if ((size_t)desc->offset < NUM_ITEMS) {
        int rc = dentry_getdents(desc, node->children, callback, ctx);
        if (IS_ERR(rc)) {
            mutex_unlock(&desc->offset_lock);
            return rc;
        }
    }
    if ((size_t)desc->offset < NUM_ITEMS) {
        mutex_unlock(&desc->offset_lock);
        return 0;
    }

    bool int_flag = push_cli();

    pid_t offset_pid = (pid_t)(desc->offset - NUM_ITEMS);
    struct process* it = all_processes;
    while (it->pid <= offset_pid) {
        it = it->next_in_all_processes;
        if (!it)
            break;
    }

    while (it) {
        char name[16];
        (void)snprintf(name, sizeof(name), "%d", it->pid);
        if (!callback(name, DT_DIR, ctx))
            break;
        desc->offset = it->pid + NUM_ITEMS;
        it = it->next_in_all_processes;
    }

    pop_cli(int_flag);
    mutex_unlock(&desc->offset_lock);
    return 0;
}

static int add_item(procfs_dir_inode* parent, const procfs_item_def* item_def) {
    procfs_item_inode* node = kmalloc(sizeof(procfs_item_inode));
    if (!node) {
        inode_unref((struct inode*)parent);
        return -ENOMEM;
    }
    *node = (procfs_item_inode){0};

    node->populate = item_def->populate;

    struct inode* inode = &node->inode;
    inode->dev = parent->inode.dev;
    inode->fops = &procfs_item_fops;
    inode->mode = S_IFREG;
    inode->ref_count = 1;

    int rc = dentry_append(&parent->children, item_def->name, inode);
    inode_unref((struct inode*)parent);
    return rc;
}

struct inode* procfs_create_root(void) {
    procfs_dir_inode* root = kmalloc(sizeof(procfs_dir_inode));
    if (!root)
        return ERR_PTR(-ENOMEM);
    *root = (procfs_dir_inode){0};

    static file_ops fops = {
        .destroy_inode = procfs_dir_destroy_inode,
        .lookup_child = procfs_root_lookup_child,
        .getdents = procfs_root_getdents,
    };

    struct inode* inode = &root->inode;
    inode->dev = vfs_generate_unnamed_device_number();
    inode->fops = &fops;
    inode->mode = S_IFDIR;
    inode->ref_count = 1;

    for (size_t i = 0; i < NUM_ITEMS; ++i) {
        inode_ref(inode);
        int rc = add_item(root, root_items + i);
        if (IS_ERR(rc))
            return ERR_PTR(rc);
    }

    return inode;
}
