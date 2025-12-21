#include <kernel/api/fcntl.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task.h>

int sys_close(int fd) { return task_free_fd(fd); }

int sys_fcntl(int fd, int cmd, unsigned long arg) {
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    switch (cmd) {
    case F_DUPFD:
        return task_alloc_fd(-1, file);
    case F_GETFL:
        return file->flags;
    case F_SETFL:
        file->flags = arg;
        return 0;
    default:
        return -EINVAL;
    }
}

int sys_fcntl64(int fd, int cmd, unsigned long arg) {
    return sys_fcntl(fd, cmd, arg);
}

int sys_dup(int oldfd) {
    struct file* file FREE(file) = task_ref_file(oldfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return task_alloc_fd(-1, file);
}

int sys_dup2(int oldfd, int newfd) {
    if (newfd < 0)
        return -EBADF;
    struct file* oldfd_file FREE(file) = task_ref_file(oldfd);
    if (IS_ERR(ASSERT(oldfd_file)))
        return PTR_ERR(oldfd_file);
    if (oldfd == newfd)
        return oldfd;
    return task_alloc_fd(newfd, oldfd_file);
}

int sys_dup3(int oldfd, int newfd, int flags) {
    (void)flags;
    if (newfd < 0)
        return -EBADF;
    struct file* oldfd_file FREE(file) = task_ref_file(oldfd);
    if (IS_ERR(ASSERT(oldfd_file)))
        return PTR_ERR(oldfd_file);
    if (oldfd == newfd)
        return -EINVAL;
    return task_alloc_fd(newfd, oldfd_file);
}

int sys_ioctl(int fd, unsigned cmd, unsigned long arg) {
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    int rc = file_ioctl(file, cmd, arg);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

int sys_pipe(int user_pipefd[2]) { return sys_pipe2(user_pipefd, 0); }

int sys_pipe2(int user_pipefd[2], int flags) {
    if (flags & O_ACCMODE)
        return -EINVAL;

    struct inode* pipe FREE(inode) = pipe_create();
    if (IS_ERR(ASSERT(pipe)))
        return PTR_ERR(pipe);

    struct file* reader_file FREE(file) = inode_open(pipe, flags | O_RDONLY);
    if (IS_ERR(ASSERT(reader_file)))
        return PTR_ERR(reader_file);

    struct file* writer_file FREE(file) = inode_open(pipe, flags | O_WRONLY);
    if (IS_ERR(ASSERT(writer_file)))
        return PTR_ERR(writer_file);

    int reader_fd = task_alloc_fd(-1, reader_file);
    if (IS_ERR(reader_fd))
        return reader_fd;

    int writer_fd = task_alloc_fd(-1, writer_file);
    if (IS_ERR(writer_fd)) {
        task_free_fd(reader_fd);
        return writer_fd;
    }

    int fds[2] = {reader_fd, writer_fd};
    if (copy_to_user(user_pipefd, fds, sizeof(int[2]))) {
        task_free_fd(writer_fd);
        task_free_fd(reader_fd);
        return -EFAULT;
    }

    return 0;
}
