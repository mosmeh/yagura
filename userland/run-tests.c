#include <errno.h>
#include <extra.h>
#include <fb.h>
#include <fcntl.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static noreturn void shm_reader(void) {
    int fd = open("/dev/shm/test-fs", O_RDWR);
    ASSERT_OK(fd);
    size_t size = 50000 * sizeof(int);
    ASSERT_OK(ftruncate(fd, size));
    int* buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        ASSERT(buf[i] == i);
    for (int i = 30000; i < 50000; ++i)
        buf[i] = i;
    ASSERT_OK(close(fd));
    ASSERT_OK(munmap(buf, size));
    exit(0);
}

static void test_fs(void) {
    puts("File system");

    unlink("/tmp/test-fs/bar");
    unlink("/tmp/test-fs/baz");
    unlink("/tmp/test-fs/qux");
    rmdir("/tmp/test-fs");

    ASSERT_OK(mkdir("/tmp/test-fs", 0));

    ASSERT_ERR(open("/tmp/test-fs/bar", 0));
    ASSERT(errno == ENOENT);

    ASSERT_OK(open("/tmp/test-fs/bar", O_CREAT | O_EXCL, 0));
    ASSERT_OK(open("/tmp/test-fs/bar", O_CREAT, 0));

    ASSERT_ERR(open("/tmp/test-fs/bar", O_CREAT | O_EXCL, 0));
    ASSERT(errno == EEXIST);

    ASSERT_ERR(open("/tmp/test-fs/bar/baz", 0));
    ASSERT(errno == ENOTDIR);

    {
        int fd = open("/tmp/test-fs/qux", O_WRONLY | O_CREAT | O_EXCL);
        ASSERT_OK(fd);
        int* buf = malloc(50000 * sizeof(int));
        ASSERT(buf);
        for (int i = 0; i < 50000; ++i)
            buf[i] = i;
        ASSERT(write(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        ASSERT(write(fd, buf, 50000 * sizeof(int)) == 50000 * sizeof(int));
        free(buf);
        ASSERT_OK(close(fd));
    }
    {
        int fd = open("/tmp/test-fs/qux", O_RDWR);
        ASSERT_OK(fd);
        int* buf = malloc(50000 * sizeof(int));
        ASSERT(buf);
        ASSERT(read(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 50000 * sizeof(int)) == 50000 * sizeof(int));
        for (int i = 0; i < 50000; ++i)
            ASSERT(buf[i] == i);
        ASSERT_OK(ftruncate(fd, 1000 * sizeof(int)));
        for (int i = 0; i < 1000; ++i)
            buf[i] = 5 * i;
        ASSERT(write(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        ASSERT_OK(close(fd));
        free(buf);
    }
    {
        int fd = open("/tmp/test-fs/qux", O_RDWR);
        ASSERT_OK(fd);
        int* buf = malloc(50000 * sizeof(int));
        ASSERT(buf);
        ASSERT(read(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 50000 * sizeof(int)) == 50000 * sizeof(int));
        for (int i = 0; i < 50000; ++i)
            ASSERT(buf[i] == 0);
        ASSERT(read(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == 5 * i);
        ASSERT_OK(ftruncate(fd, 1000 * sizeof(int)));
        ASSERT_OK(close(fd));
    }
    {
        int fd = open("/tmp/test-fs/qux", O_RDONLY);
        ASSERT_OK(fd);
        int* buf = malloc(50000 * sizeof(int));
        ASSERT(buf);
        ASSERT(read(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 50000 * sizeof(int)) == 0);
        ASSERT_OK(close(fd));
    }
    unlink("/dev/shm/test-fs");
    {
        int fd = open("/dev/shm/test-fs", O_RDWR | O_CREAT | O_EXCL);
        ASSERT_OK(fd);
        size_t size = 30000 * sizeof(int);
        ASSERT_OK(ftruncate(fd, size));
        int* buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        ASSERT(buf != MAP_FAILED);
        for (int i = 0; i < 30000; ++i)
            buf[i] = i;
        pid_t pid = fork();
        ASSERT_OK(pid);
        if (pid == 0)
            shm_reader();
        ASSERT_OK(waitpid(pid, NULL, 0));
        ASSERT_OK(close(fd));
        ASSERT_OK(munmap(buf, size));
    }
    {
        int fd = open("/dev/shm/test-fs", O_RDWR);
        ASSERT_OK(fd);
        size_t size = 50000 * sizeof(int);
        int* buf = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
        ASSERT(buf != MAP_FAILED);
        for (int i = 0; i < 30000; ++i)
            ASSERT(buf[i] == i);
        for (int i = 30000; i < 50000; ++i)
            ASSERT(buf[i] == i);
        ASSERT_OK(munmap(buf, size));
        ASSERT_OK(close(fd));
    }
    {
        int fd = open("/dev/shm/test-fs", O_RDWR);
        ASSERT_OK(fd);
        size_t size = 50000 * sizeof(int);
        int* buf = malloc(size);
        ASSERT(buf);
        ASSERT((size_t)read(fd, buf, size) == size);
        ASSERT_OK(close(fd));
        for (int i = 0; i < 30000; ++i)
            ASSERT(buf[i] == i);
        for (int i = 30000; i < 50000; ++i)
            ASSERT(buf[i] == i);
        free(buf);
    }
}

static size_t read_all(int fd, unsigned char* buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, buf + total, count - total);
        ASSERT_OK(n);
        total += n;
    }
    return total;
}

static size_t write_all(int fd, unsigned char* buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t nwritten = write(fd, buf + total, count - total);
        ASSERT_OK(nwritten);
        total += nwritten;
    }
    return total;
}

static noreturn void pipe_peer(int send_fd, int recv_fd) {
    static unsigned buf[1024];
    size_t total = 0;
    for (size_t i = 0; i < 10000; i += 1024) {
        size_t s = MIN(1024, 10000 - i) * sizeof(unsigned);
        ASSERT(read_all(recv_fd, (unsigned char*)buf, s) == s);
        for (size_t j = 0; j < s / sizeof(unsigned); ++j)
            ASSERT(buf[j] == total / sizeof(unsigned) + j);
        total += s;
    }

    int flag = fcntl(recv_fd, F_GETFL);
    ASSERT_OK(flag);
    ASSERT_OK(fcntl(recv_fd, F_SETFL, flag | O_NONBLOCK));

    char c;
    errno = 0;
    ASSERT_ERR(read(recv_fd, &c, 1));
    ASSERT(errno == EAGAIN);

    ASSERT(write_all(send_fd, (unsigned char*)"x", 1) == 1);

    ASSERT_OK(close(send_fd));
    ASSERT_OK(close(recv_fd));

    exit(0);
}

static void test_fifo(void) {
    puts("FIFO");

    ASSERT(poll(NULL, 0, 10) == 0);

    int recv_fds[2];
    ASSERT_OK(pipe(recv_fds));

    struct pollfd pollfds1[] = {
        {.fd = recv_fds[0], .events = POLLIN},
    };
    ASSERT(poll(pollfds1, 1, 0) == 0);
    ASSERT(poll(pollfds1, 1, 10) == 0);

    int send_fds[2];
    ASSERT_OK(pipe(send_fds));

    pid_t pid = fork();
    ASSERT_OK(pid);
    if (pid == 0)
        pipe_peer(recv_fds[1], send_fds[0]);

    static unsigned buf[10000];
    for (size_t i = 0; i < 10000; ++i)
        buf[i] = i;
    ASSERT(write_all(send_fds[1], (unsigned char*)buf, sizeof(buf)) ==
           sizeof(buf));

    int dummy_fds[2];
    ASSERT_OK(pipe(dummy_fds));

    struct pollfd pollfds2[] = {
        {.fd = dummy_fds[0], .events = POLLIN},
        {.fd = recv_fds[0], .events = POLLIN},
    };
    ASSERT(poll(pollfds2, 2, -1) == 1);
    ASSERT(pollfds2[0].revents == 0);
    ASSERT(pollfds2[1].revents == POLLIN);

    int flag = fcntl(send_fds[1], F_GETFL);
    ASSERT_OK(flag);
    ASSERT_OK(fcntl(send_fds[1], F_SETFL, flag | O_NONBLOCK));

    int nwritten;
    errno = 0;
    while ((nwritten = write(send_fds[1], buf, sizeof(buf))) > 0)
        ;
    ASSERT(nwritten < 0);
    ASSERT(errno == EAGAIN);

    struct pollfd pollfds3[] = {
        {.fd = send_fds[1], .events = POLLOUT},
        {.fd = dummy_fds[1], .events = POLLOUT},
    };
    ASSERT(poll(pollfds3, 2, -1) == 1);
    ASSERT(pollfds3[0].revents == 0);
    ASSERT(pollfds3[1].revents == POLLOUT);

    ASSERT_OK(waitpid(pid, NULL, 0));

    ASSERT_OK(close(send_fds[0]));
    ASSERT_OK(close(recv_fds[1]));
    ASSERT_OK(close(dummy_fds[0]));
    ASSERT_OK(close(dummy_fds[1]));

    struct pollfd pollfds4[] = {{.fd = send_fds[1]}, {.fd = recv_fds[0]}};
    ASSERT(poll(pollfds4, 2, -1) == 2);
    ASSERT(pollfds4[0].revents == POLLERR);
    ASSERT(pollfds4[1].revents == POLLHUP);

    ASSERT_OK(close(send_fds[1]));
    ASSERT_OK(close(recv_fds[0]));
}

static noreturn void socket_receiver(bool shut_rd) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_OK(sockfd);
    struct sockaddr_un addr = {AF_UNIX, "/tmp/test-socket"};
    ASSERT_OK(connect(sockfd, (const struct sockaddr*)&addr,
                      sizeof(struct sockaddr_un)));

    errno = 0;
    ASSERT_ERR(connect(sockfd, (const struct sockaddr*)&addr,
                       sizeof(struct sockaddr_un)));
    ASSERT(errno == EISCONN);

    ASSERT_OK(shutdown(sockfd, SHUT_WR));

    static unsigned buf[1024];
    size_t total = 0;
    for (size_t i = 0; i < 55000; i += 1024) {
        size_t s = MIN(1024, 55000 - i) * sizeof(unsigned);
        ASSERT(read_all(sockfd, (unsigned char*)buf, s) == s);
        for (size_t j = 0; j < s / sizeof(unsigned); ++j)
            ASSERT(buf[j] == total / sizeof(unsigned) + j);
        total += s;
    }

    if (shut_rd)
        ASSERT_OK(shutdown(sockfd, SHUT_RD));

    char c;
    ASSERT(read(sockfd, &c, 1) == 0);

    ASSERT_OK(close(sockfd));
    exit(0);
}

static void test_socket(void) {
    puts("Socket");

    unlink("/tmp/test-socket");
    unlink("/tmp/test-socket2");
    unlink("/tmp/test-socket3");
    struct sockaddr_un addr = {AF_UNIX, "/tmp/test-socket"};
    struct sockaddr_un addr2 = {AF_UNIX, "/tmp/test-socket2"};
    struct sockaddr_un addr3 = {AF_UNIX, "/tmp/test-socket3"};

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_OK(sockfd);

    int sockfd2 = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_OK(sockfd2);
    ASSERT_OK(bind(sockfd2, (const struct sockaddr*)&addr2,
                   sizeof(struct sockaddr_un)));
    ASSERT_OK(listen(sockfd2, 1));

    errno = 0;
    ASSERT_ERR(listen(sockfd, 1));
    ASSERT(errno == EINVAL);

    errno = 0;
    ASSERT_ERR(accept(sockfd, NULL, NULL));
    ASSERT(errno == EINVAL);

    ASSERT_OK(bind(sockfd, (const struct sockaddr*)&addr,
                   sizeof(struct sockaddr_un)));

    errno = 0;
    ASSERT_ERR(bind(sockfd, (const struct sockaddr*)&addr,
                    sizeof(struct sockaddr_un)));
    ASSERT(errno == EADDRINUSE);

    errno = 0;
    ASSERT_ERR(bind(sockfd, (const struct sockaddr*)&addr3,
                    sizeof(struct sockaddr_un)));
    ASSERT(errno == EINVAL);

    errno = 0;
    ASSERT_ERR(accept(sockfd, NULL, NULL));
    ASSERT(errno == EINVAL);

    ASSERT_OK(listen(sockfd, 1));
    ASSERT_OK(listen(sockfd, 2));

    errno = 0;
    ASSERT_ERR(connect(sockfd, (const struct sockaddr*)&addr2,
                       sizeof(struct sockaddr_un)));
    ASSERT(errno == EINVAL);

    errno = 0;
    ASSERT_ERR(read(sockfd, "x", 1));
    ASSERT(errno == EINVAL);

    char c = 'x';
    errno = 0;
    ASSERT_ERR(write(sockfd, &c, 1));
    ASSERT(errno == ENOTCONN);

    pid_t pid1 = fork();
    ASSERT_OK(pid1);
    if (pid1 == 0)
        socket_receiver(false);
    pid_t pid2 = fork();
    ASSERT_OK(pid2);
    if (pid2 == 0)
        socket_receiver(true);

    int peer_fd1 = accept(sockfd, NULL, NULL);
    ASSERT_OK(peer_fd1);
    int peer_fd2 = accept(sockfd, NULL, NULL);
    ASSERT_OK(peer_fd2);

    ASSERT_OK(shutdown(peer_fd1, SHUT_RD));
    ASSERT(read(peer_fd1, &c, 1) == 0);

    static unsigned buf[10000];
    for (size_t j = 0; j < 10000; ++j)
        buf[j] = j;
    for (size_t i = 0; i < 55000; i += 10000) {
        size_t s = MIN(10000, 55000 - i) * sizeof(unsigned);
        ASSERT(write_all(peer_fd1, (unsigned char*)buf, s) == s);
        ASSERT(write_all(peer_fd2, (unsigned char*)buf, s) == s);
        for (size_t j = 0; j < 10000; ++j)
            buf[j] += 10000;
    }

    ASSERT_OK(shutdown(peer_fd1, SHUT_WR));

    ASSERT_OK(waitpid(pid1, NULL, 0));
    ASSERT_OK(waitpid(pid2, NULL, 0));

    ASSERT_OK(close(sockfd));
    ASSERT_OK(close(sockfd2));
    ASSERT_OK(close(peer_fd1));
    ASSERT_OK(close(peer_fd2));
}

static void test_mmap_private(void) {
    puts("mmap(MAP_PRIVATE)");
    mkdir("/tmp/test-mmap-private", 0);
    int fd = open("/tmp/test-mmap-private/foo", O_CREAT | O_RDWR);
    ASSERT_OK(fd);

    size_t size = 30000 * sizeof(int);
    ASSERT_OK(ftruncate(fd, size));

    int* buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        buf[i] = i;
    ASSERT_OK(munmap(buf, size));

    buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i) {
        ASSERT(buf[i] == i);
        buf[i] = i + 30000;
    }
    ASSERT_OK(munmap(buf, size));

    buf = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        ASSERT(buf[i] == i);
    ASSERT_OK(munmap(buf, size));

    buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        ASSERT(buf[i] == i);
    ASSERT_OK(munmap(buf, size));

    ASSERT_OK(close(fd));
}

static void* shared_mmap_addr;

static void mmap_reader(void) {
    for (size_t i = 0; i < 100; ++i)
        ASSERT(((uint32_t*)shared_mmap_addr)[i] == i);
    ASSERT_OK(munmap(shared_mmap_addr, 5000));
    exit(0);
}

static void test_mmap_shared(void) {
    puts("mmap(MAP_SHARED)");
    size_t size = 5000;
    shared_mmap_addr = mmap(NULL, size, PROT_READ | PROT_WRITE,

                            MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    ASSERT(shared_mmap_addr != MAP_FAILED);
    for (size_t i = 0; i < 100; ++i)
        ((uint32_t*)shared_mmap_addr)[i] = i;
    pid_t pid = fork();
    ASSERT_OK(pid);
    if (pid == 0)
        mmap_reader();
    ASSERT_OK(waitpid(pid, NULL, 0));
    ASSERT_OK(munmap(shared_mmap_addr, size));
}

static void test_framebuffer(void) {
    puts("Framebuffer");

    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) {
        ASSERT(errno == ENOENT);
        return;
    }

    struct fb_info fb_info;
    ASSERT_OK(ioctl(fd, FBIOGET_INFO, &fb_info));

    size_t size = fb_info.pitch * fb_info.height;
    void* fb = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ASSERT_OK(close(fd));
    ASSERT(fb != MAP_FAILED);
    void* buf = malloc(size);
    ASSERT(buf);
    memcpy(buf, fb, size);
    memcpy(fb, buf, size);
    free(buf);
    ASSERT_OK(munmap(fb, size));
}

static void test_malloc(void) {
    puts("malloc");
    free(malloc(0));
    for (size_t i = 0; i < 10000; ++i) {
        void* buf = malloc(1);
        ASSERT(buf);
        void* buf2 = malloc(100000);
        ASSERT(buf2);
        free(buf);
        free(buf2);
    }
}

int main(void) {
    test_fs();
    test_fifo();
    test_socket();
    test_mmap_private();
    test_mmap_shared();
    test_framebuffer();
    test_malloc();

    return EXIT_SUCCESS;
}
