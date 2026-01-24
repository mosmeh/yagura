#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

long sys_close(int fd) { return files_free_fd(current->files, fd); }

#define SETFL_MASK O_NONBLOCK

long sys_fcntl(int fd, int cmd, unsigned long arg) {
    struct files* files = current->files;
    struct file* file FREE(file) = files_ref_file(files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    switch (cmd) {
    case F_DUPFD:
        return files_alloc_fd(files, -1, file);
    case F_GETFL:
        return file->flags;
    case F_SETFL:
        file->flags = (file->flags & ~SETFL_MASK) | (arg & SETFL_MASK);
        return 0;
    default:
        return -EINVAL;
    }
}

long sys_fcntl64(int fd, int cmd, unsigned long arg) {
    return sys_fcntl(fd, cmd, arg);
}

long sys_dup(int oldfd) {
    struct files* files = current->files;
    struct file* file FREE(file) = files_ref_file(files, oldfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return files_alloc_fd(files, -1, file);
}

long sys_dup2(int oldfd, int newfd) {
    if (newfd < 0)
        return -EBADF;
    struct files* files = current->files;
    struct file* oldfd_file FREE(file) = files_ref_file(files, oldfd);
    if (IS_ERR(ASSERT(oldfd_file)))
        return PTR_ERR(oldfd_file);
    if (oldfd == newfd)
        return oldfd;
    return files_alloc_fd(files, newfd, oldfd_file);
}

long sys_dup3(int oldfd, int newfd, int flags) {
    (void)flags;
    if (oldfd == newfd)
        return -EINVAL;
    if (newfd < 0)
        return -EBADF;
    struct files* files = current->files;
    struct file* oldfd_file FREE(file) = files_ref_file(files, oldfd);
    if (IS_ERR(ASSERT(oldfd_file)))
        return PTR_ERR(oldfd_file);
    return files_alloc_fd(files, newfd, oldfd_file);
}

long sys_ioctl(int fd, unsigned cmd, unsigned long arg) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    int rc = file_ioctl(file, cmd, arg);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

long sys_pipe(int user_pipefd[2]) { return sys_pipe2(user_pipefd, 0); }

long sys_pipe2(int user_pipefd[2], int flags) {
    if (flags & O_ACCMODE)
        return -EINVAL;
    flags &= ~O_KERNEL_INTERNAL_MASK;

    struct inode* pipe FREE(inode) = pipe_create();
    if (IS_ERR(ASSERT(pipe)))
        return PTR_ERR(pipe);

    struct file* reader_file FREE(file) = inode_open(pipe, flags | O_RDONLY);
    if (IS_ERR(ASSERT(reader_file)))
        return PTR_ERR(reader_file);

    struct file* writer_file FREE(file) = inode_open(pipe, flags | O_WRONLY);
    if (IS_ERR(ASSERT(writer_file)))
        return PTR_ERR(writer_file);

    struct files* files = current->files;

    int reader_fd = files_alloc_fd(files, -1, reader_file);
    if (IS_ERR(reader_fd))
        return reader_fd;

    int writer_fd = files_alloc_fd(files, -1, writer_file);
    if (IS_ERR(writer_fd)) {
        files_free_fd(files, reader_fd);
        return writer_fd;
    }

    int fds[2] = {reader_fd, writer_fd};
    if (copy_to_user(user_pipefd, fds, sizeof(int[2]))) {
        files_free_fd(files, writer_fd);
        files_free_fd(files, reader_fd);
        return -EFAULT;
    }

    return 0;
}
