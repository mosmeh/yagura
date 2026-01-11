#include "private.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stdio.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/poll.h>
#include <kernel/fs/file.h>
#include <kernel/fs/path.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/safe_string.h>
#include <kernel/sched.h>

static struct slab file_slab;

void file_init(void) { slab_init(&file_slab, "file", sizeof(struct file)); }

struct file* file_create(struct inode* inode, int flags) {
    struct file* file = slab_alloc(&file_slab);
    if (IS_ERR(ASSERT(file)))
        return file;
    *file = (struct file){
        .inode = inode_ref(inode),
        .fops = inode->fops,
        .filemap = inode->filemap,
        .flags = flags,
        .refcount = REFCOUNT_INIT_ONE,
    };
    return file;
}

void __file_destroy(struct file* file) {
    struct inode* inode = file->inode;
    if (file->fops->close)
        file->fops->close(file);
    path_destroy_recursive(file->path);
    slab_free(&file_slab, file);
    inode_unref(inode);
}

ssize_t file_read(struct file* file, void* user_buffer, size_t count) {
    if (!user_buffer || !is_user_range(user_buffer, count))
        return -EFAULT;
    SCOPED_LOCK(file, file);
    ssize_t nread = file_pread(file, user_buffer, count, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    return nread;
}

NODISCARD
static ssize_t default_file_pread(struct file* file, void* user_buffer,
                                  size_t count, uint64_t offset) {
    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    if (!inode->iops->pread)
        return -EINVAL;

    SCOPED_LOCK(inode, inode);

    if (offset >= inode->size)
        return 0;

    count = MIN(count, inode->size - offset);

    unsigned char* user_dest = user_buffer;
    size_t nread = 0;
    size_t page_index = offset >> PAGE_SHIFT;
    size_t page_offset = offset % PAGE_SIZE;
    while (nread < count) {
        struct page* page = filemap_ensure_page(filemap, page_index, false);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            break;

        unsigned char page_buf[PAGE_SIZE];
        size_t to_read = MIN(count - nread, PAGE_SIZE - page_offset);
        page_copy_to_buffer(page, page_buf, page_offset, to_read);
        if (copy_to_user(user_dest, page_buf, to_read))
            return -EFAULT;

        user_dest += to_read;
        nread += to_read;
        ++page_index;
        page_offset = 0;
    }

    return nread;
}

ssize_t file_pread(struct file* file, void* user_buffer, size_t count,
                   uint64_t offset) {
    if (!user_buffer || !is_user_range(user_buffer, count))
        return -EFAULT;
    if (S_ISDIR(file->inode->mode))
        return -EISDIR;
    if ((file->flags & O_ACCMODE) == O_WRONLY)
        return -EBADF;
    if (offset + count < offset)
        return -EOVERFLOW;
    if (file->fops->pread)
        return file->fops->pread(file, user_buffer, count, offset);
    return default_file_pread(file, user_buffer, count, offset);
}

ssize_t file_write(struct file* file, const void* user_buffer, size_t count) {
    if (!user_buffer || !is_user_range(user_buffer, count))
        return -EFAULT;
    SCOPED_LOCK(file, file);
    ssize_t nwritten = file_pwrite(file, user_buffer, count, file->offset);
    if (IS_OK(nwritten))
        file->offset += nwritten;
    return nwritten;
}

NODISCARD
static ssize_t default_file_pwrite(struct file* file, const void* user_buffer,
                                   size_t count, uint64_t offset) {
    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    if (!inode->iops->pwrite)
        return -EINVAL;

    const unsigned char* user_src = user_buffer;
    size_t nwritten = 0;
    size_t page_index = offset >> PAGE_SHIFT;
    size_t page_offset = offset % PAGE_SIZE;
    SCOPED_LOCK(inode, inode);
    while (nwritten < count) {
        struct page* page = filemap_ensure_page(filemap, page_index, true);
        if (IS_ERR(ASSERT(page)))
            return PTR_ERR(page);

        char page_buf[PAGE_SIZE];
        size_t to_write = MIN(count - nwritten, PAGE_SIZE - page_offset);
        if (copy_from_user(page_buf, user_src, to_write))
            return -EFAULT;
        page_copy_from_buffer(page, page_buf, page_offset, to_write);

        user_src += to_write;
        nwritten += to_write;
        ++page_index;
        page_offset = 0;

        page->flags |= PAGE_DIRTY;
        inode->flags |= INODE_DIRTY;
        inode->size = MAX(inode->size, offset + nwritten);
    }
    return nwritten;
}

ssize_t file_pwrite(struct file* file, const void* user_buffer, size_t count,
                    uint64_t offset) {
    if (!user_buffer || !is_user_range(user_buffer, count))
        return -EFAULT;
    if (S_ISDIR(file->inode->mode))
        return -EISDIR;
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EBADF;
    if (offset + count < offset)
        return -EOVERFLOW;
    if (file->fops->pwrite)
        return file->fops->pwrite(file, user_buffer, count, offset);
    return default_file_pwrite(file, user_buffer, count, offset);
}

int file_truncate(struct file* file, uint64_t length) {
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EINVAL;
    return inode_truncate(file->filemap->inode, length);
}

int file_sync(struct file* file, uint64_t offset, uint64_t nbytes) {
    return inode_sync(file->filemap->inode, offset, nbytes);
}

loff_t file_seek(struct file* file, loff_t offset, int whence) {
    struct inode* inode = file->filemap->inode;
    switch (inode->mode & S_IFMT) {
    case S_IFREG:
    case S_IFBLK:
    case S_IFLNK:
        break;
    default:
        return -ESPIPE;
    }

    switch (whence) {
    case SEEK_SET: {
        if (offset < 0)
            return -EINVAL;
        SCOPED_LOCK(file, file);
        file->offset = offset;
        return offset;
    }
    case SEEK_CUR: {
        SCOPED_LOCK(file, file);
        loff_t new_offset = (loff_t)file->offset + offset;
        if (new_offset < 0)
            return -EINVAL;
        file->offset = new_offset;
        return new_offset;
    }
    case SEEK_END: {
        SCOPED_LOCK(inode, inode);
        loff_t size = (loff_t)inode->size;
        loff_t new_offset = size + offset;
        if (size < 0 || new_offset < 0)
            return -EINVAL;
        SCOPED_LOCK(file, file);
        file->offset = new_offset;
        return new_offset;
    }
    default:
        return -EINVAL;
    }
}

NODISCARD static ssize_t default_file_readlink(struct file* file, char* buffer,
                                               size_t bufsiz) {
    STATIC_ASSERT(SYMLINK_MAX <= PAGE_SIZE);

    char page_buf[PAGE_SIZE];
    {
        struct filemap* filemap = file->filemap;
        struct inode* inode = filemap->inode;

        SCOPED_LOCK(inode, inode);

        struct page* page = filemap_ensure_page(filemap, 0, false);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            return -EINVAL;

        page_copy_to_buffer(page, page_buf, 0, bufsiz);
    }

    size_t len = strnlen(page_buf, bufsiz);
    memcpy(buffer, page_buf, len);
    return len;
}

ssize_t file_readlink(struct file* file, char* buffer, size_t bufsiz) {
    if (!S_ISLNK(file->inode->mode))
        return -EINVAL;

    bufsiz = MIN(bufsiz, SYMLINK_MAX);

    if (file->fops->readlink)
        return file->fops->readlink(file, buffer, bufsiz);

    return default_file_readlink(file, buffer, bufsiz);
}

int file_symlink(struct file* file, const char* target) {
    if (!S_ISLNK(file->inode->mode))
        return -EINVAL;

    STATIC_ASSERT(SYMLINK_MAX <= PAGE_SIZE);

    size_t len = strnlen(target, SYMLINK_MAX + 1);
    if (len > SYMLINK_MAX)
        return -ENAMETOOLONG;

    int rc = file_truncate(file, len);
    if (IS_ERR(rc))
        return rc;

    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;

    SCOPED_LOCK(inode, inode);

    struct page* page = filemap_ensure_page(filemap, 0, true);
    if (IS_ERR(ASSERT(page)))
        return PTR_ERR(page);

    unsigned char* mapped_page = kmap_page(page);
    memcpy(mapped_page, target, len);
    memset(mapped_page + len, 0, PAGE_SIZE - len);
    kunmap(mapped_page);

    page->flags = ~0;
    inode->flags |= INODE_DIRTY;

    return 0;
}

int file_ioctl(struct file* file, unsigned cmd, unsigned long arg) {
    if (!file->fops->ioctl)
        return -ENOTTY;
    return file->fops->ioctl(file, cmd, arg);
}

int file_getdents(struct file* file, getdents_callback_fn callback, void* ctx) {
    if (!file->fops->getdents || !S_ISDIR(file->inode->mode))
        return -ENOTDIR;
    return file->fops->getdents(file, callback, ctx);
}

short file_poll(struct file* file, short events) {
    if (!file->fops->poll)
        return events & (POLLIN | POLLOUT);
    short revents = file->fops->poll(file, events);
    ASSERT(revents >= 0);
    if (!(events & POLLIN))
        ASSERT(!(revents & POLLIN));
    if (!(events & POLLOUT))
        ASSERT(!(revents & POLLOUT));
    return revents;
}

struct vm_obj* file_mmap(struct file* file) {
    if (file->fops->mmap)
        return file->fops->mmap(file);
    return vm_obj_ref(&file->filemap->inode->vm_obj);
}

struct block_ctx {
    struct file* file;
    bool (*unblock)(struct file*);
};

static bool should_unblock(void* data) {
    struct block_ctx* ctx = data;
    return ctx->unblock(ctx->file);
}

int file_block(struct file* file, bool (*unblock)(struct file*), int flags) {
    if (unblock(file))
        return 0;
    if (file->flags & O_NONBLOCK)
        return -EAGAIN;
    struct block_ctx ctx = {
        .file = file,
        .unblock = unblock,
    };
    return sched_block(should_unblock, &ctx, flags);
}
