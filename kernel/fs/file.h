#pragma once

#include <kernel/api/sys/types.h>
#include <kernel/lock.h>
#include <kernel/resource.h>

// Open file description
struct file {
    struct inode* inode;
    const struct file_ops* fops;
    struct filemap* filemap;
    atomic_int flags;
    uint64_t offset;
    void* private_data;

    struct mutex lock;
    refcount_t refcount;
};

typedef bool (*getdents_callback_fn)(const char* name, ino_t,
                                     unsigned char type, void* ctx);

struct file_ops {
    int (*open)(struct file*);
    int (*close)(struct file*);
    ssize_t (*pread)(struct file*, void* user_buffer, size_t count,
                     uint64_t offset);
    ssize_t (*pwrite)(struct file*, const void* user_buffer, size_t count,
                      uint64_t offset);
    ssize_t (*readlink)(struct file*, char* buffer, size_t bufsiz);
    int (*ioctl)(struct file*, unsigned cmd, unsigned long arg);
    int (*getdents)(struct file*, getdents_callback_fn, void* ctx);
    short (*poll)(struct file*, short events);
    struct vm_obj* (*mmap)(struct file*);
};

struct file* file_ref(struct file*);
void file_unref(struct file*);

DEFINE_FREE(file, struct file*, file_unref)

NODISCARD ssize_t file_read(struct file*, void* user_buffer, size_t count);
NODISCARD ssize_t file_pread(struct file*, void* user_buffer, size_t count,
                             uint64_t offset);
NODISCARD ssize_t file_write(struct file*, const void* user_buffer,
                             size_t count);
NODISCARD ssize_t file_pwrite(struct file*, const void* user_buffer,
                              size_t count, uint64_t offset);

NODISCARD int file_truncate(struct file*, uint64_t length);
NODISCARD int file_sync(struct file*, uint64_t offset, uint64_t nbytes);
NODISCARD loff_t file_seek(struct file*, loff_t offset, int whence);

NODISCARD ssize_t file_readlink(struct file*, char* buffer, size_t bufsiz);
NODISCARD int file_symlink(struct file*, const char* target);

NODISCARD int file_ioctl(struct file*, unsigned cmd, unsigned long arg);
NODISCARD int file_getdents(struct file*, getdents_callback_fn, void* ctx);
NODISCARD short file_poll(struct file*, short events);

NODISCARD struct vm_obj* file_mmap(struct file*);

NODISCARD int file_block(struct file*, bool (*unblock)(struct file*),
                         int flags);
