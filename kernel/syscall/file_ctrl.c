#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/vfs.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

SYSCALL1(close, int, fd) { return fd_table_free_fd(current->fd_table, fd); }

#define SETFL_MASK O_NONBLOCK

NODISCARD static int fcntl(int fd, int cmd, unsigned long arg) {
    struct fd_table* fd_table = current->fd_table;
    switch (cmd) {
    case F_DUPFD:
    case F_DUPFD_CLOEXEC: {
        struct file* file FREE(file) = ASSERT(fd_table_ref_file(fd_table, fd));
        if (IS_ERR(file))
            return PTR_ERR(file);
        if (arg >= OPEN_MAX)
            return -EINVAL;
        int fd_flags = 0;
        if (cmd == F_DUPFD_CLOEXEC)
            fd_flags |= FD_CLOEXEC;
        return fd_table_alloc_fd(fd_table, arg, file, fd_flags);
    }
    case F_GETFD:
        return fd_table_get_flags(fd_table, fd);
    case F_SETFD:
        return fd_table_set_flags(fd_table, fd, arg);
    case F_GETFL: {
        struct file* file FREE(file) = ASSERT(fd_table_ref_file(fd_table, fd));
        if (IS_ERR(file))
            return PTR_ERR(file);
        return file->flags;
    }
    case F_SETFL: {
        struct file* file FREE(file) = ASSERT(fd_table_ref_file(fd_table, fd));
        if (IS_ERR(file))
            return PTR_ERR(file);
        file->flags = (file->flags & ~SETFL_MASK) | (arg & SETFL_MASK);
        return 0;
    }
    case F_SETPIPE_SZ:
    case F_GETPIPE_SZ: {
        struct file* file FREE(file) = ASSERT(fd_table_ref_file(fd_table, fd));
        if (IS_ERR(file))
            return PTR_ERR(file);
        return pipe_fcntl(file, cmd, arg);
    }
    default:
        return -EINVAL;
    }
}

SYSCALL3(fcntl, int, fd, int, cmd, unsigned long, arg) {
    return fcntl(fd, cmd, arg);
}

SYSCALL3(fcntl64, int, fd, int, cmd, unsigned long, arg) {
    return fcntl(fd, cmd, arg);
}

SYSCALL1(dup, int, oldfd) {
    struct fd_table* fd_table = current->fd_table;
    struct file* file FREE(file) = ASSERT(fd_table_ref_file(fd_table, oldfd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    return fd_table_alloc_fd(fd_table, 0, file, 0);
}

SYSCALL2(dup2, int, oldfd, int, newfd) {
    if (newfd < 0)
        return -EBADF;
    struct fd_table* fd_table = current->fd_table;
    struct file* oldfd_file FREE(file) =
        ASSERT(fd_table_ref_file(fd_table, oldfd));
    if (IS_ERR(oldfd_file))
        return PTR_ERR(oldfd_file);
    if (oldfd == newfd)
        return oldfd;
    int rc = fd_table_set_file(fd_table, newfd, oldfd_file, 0);
    if (IS_ERR(rc))
        return rc;
    return newfd;
}

SYSCALL3(dup3, int, oldfd, int, newfd, int, flags) {
    if (flags & ~O_CLOEXEC)
        return -EINVAL;
    if (oldfd == newfd)
        return -EINVAL;
    if (newfd < 0)
        return -EBADF;
    struct fd_table* fd_table = current->fd_table;
    struct file* oldfd_file FREE(file) =
        ASSERT(fd_table_ref_file(fd_table, oldfd));
    if (IS_ERR(oldfd_file))
        return PTR_ERR(oldfd_file);
    int fd_flags = 0;
    if (flags & O_CLOEXEC)
        fd_flags |= FD_CLOEXEC;
    int rc = fd_table_set_file(fd_table, newfd, oldfd_file, fd_flags);
    if (IS_ERR(rc))
        return rc;
    return newfd;
}

SYSCALL3(ioctl, int, fd, unsigned, cmd, unsigned long, arg) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    int rc = file_ioctl(file, cmd, arg);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

NODISCARD static int pipe2(int user_pipefd[2], int flags) {
    if (flags & O_ACCMODE)
        return -EINVAL;
    flags &= ~O_KERNEL_INTERNAL_MASK;

    int fd_flags = 0;
    if (flags & O_CLOEXEC) {
        fd_flags |= FD_CLOEXEC;
        flags &= ~O_CLOEXEC;
    }

    struct inode* pipe FREE(inode) = ASSERT(pipe_create());
    if (IS_ERR(pipe))
        return PTR_ERR(pipe);

    struct file* reader_file FREE(file) =
        ASSERT(inode_open(pipe, flags | O_RDONLY));
    if (IS_ERR(reader_file))
        return PTR_ERR(reader_file);

    struct file* writer_file FREE(file) =
        ASSERT(inode_open(pipe, flags | O_WRONLY));
    if (IS_ERR(writer_file))
        return PTR_ERR(writer_file);

    struct fd_table* fd_table = current->fd_table;

    int reader_fd = fd_table_alloc_fd(fd_table, 0, reader_file, fd_flags);
    if (IS_ERR(reader_fd))
        return reader_fd;

    int writer_fd = fd_table_alloc_fd(fd_table, 0, writer_file, fd_flags);
    if (IS_ERR(writer_fd)) {
        fd_table_free_fd(fd_table, reader_fd);
        return writer_fd;
    }

    int fds[2] = {reader_fd, writer_fd};
    if (copy_to_user(user_pipefd, fds, sizeof(int[2]))) {
        fd_table_free_fd(fd_table, writer_fd);
        fd_table_free_fd(fd_table, reader_fd);
        return -EFAULT;
    }

    return 0;
}

SYSCALL1(pipe, int*, user_pipefd) { return pipe2(user_pipefd, 0); }

SYSCALL2(pipe2, int*, user_pipefd, int, flags) {
    return pipe2(user_pipefd, flags);
}
