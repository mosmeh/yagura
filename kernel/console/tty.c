#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/api/termios.h>
#include <kernel/fs/file.h>
#include <kernel/panic.h>
#include <kernel/task/signal.h>

static const cc_t ttydefchars[LINUX_NCCS] = {
    [VINTR] = CINTR,       [VQUIT] = CQUIT,       [VERASE] = CERASE,
    [VKILL] = CKILL,       [VEOF] = CEOF,         [VTIME] = CTIME,
    [VMIN] = CMIN,         [VSWTC] = CSWTC,       [VSTART] = CSTART,
    [VSTOP] = CSTOP,       [VSUSP] = CSUSP,       [VEOL] = CEOL,
    [VREPRINT] = CREPRINT, [VDISCARD] = CDISCARD, [VWERASE] = CWERASE,
    [VLNEXT] = CLNEXT,     [VEOL2] = CEOL2,
};

static const struct ktermios default_termios = {
    .c_iflag = TTYDEF_IFLAG,
    .c_oflag = TTYDEF_OFLAG,
    .c_cflag = TTYDEF_CFLAG,
    .c_lflag = TTYDEF_LFLAG,
    .c_ispeed = TTYDEF_SPEED,
    .c_ospeed = TTYDEF_SPEED,
};

int tty_register(struct tty* tty) {
    ASSERT(tty->dev > 0);
    ASSERT(tty->ops);

    switch (major(tty->dev)) {
    case TTY_MAJOR:
    case TTYAUX_MAJOR:
        break;
    default:
        return -EINVAL;
    }

    STATIC_ASSERT(PAGE_SIZE % sizeof(struct attr_char) == 0);
    tty->input_buf = ring_buf_create(PAGE_SIZE);
    if (IS_ERR(tty->input_buf))
        return PTR_ERR(tty->input_buf);

    struct char_dev* char_dev = &tty->char_dev;
    strlcpy(char_dev->name, tty->name, sizeof(char_dev->name));
    char_dev->dev = tty->dev;
    char_dev->fops = &tty_fops;

    tty->termios = default_termios;
    memcpy(tty->termios.c_cc, ttydefchars, sizeof(tty->termios.c_cc));

    if (!tty->num_columns)
        tty->num_columns = 80;
    if (!tty->num_rows)
        tty->num_rows = 25;

    int rc = char_dev_register(char_dev);
    if (IS_ERR(rc)) {
        ring_buf_destroy(tty->input_buf);
        return rc;
    }

    return 0;
}

static int tty_open(struct file* file) {
    struct char_dev* char_dev = char_dev_get(file->inode->rdev);
    if (!char_dev)
        return -ENODEV;
    struct tty* tty = CONTAINER_OF(char_dev, struct tty, char_dev);
    file->private_data = tty;
    return 0;
}

static struct tty* tty_from_file(struct file* file) {
    return file->private_data;
}

static bool can_read(const struct tty* tty) {
    return !ring_buf_is_empty(tty->input_buf);
}

static bool unblock_read(struct file* file) {
    return can_read(tty_from_file(file));
}

static ssize_t tty_pread(struct file* file, void* user_buf, size_t count,
                         uint64_t offset) {
    (void)offset;

    char* user_dest = user_buf;

    // Ensure no page faults occur while spinlock is held
    int rc = vm_populate(user_dest, user_dest + count, VM_WRITE);
    if (IS_ERR(rc))
        return rc;

    struct tty* tty = tty_from_file(file);
    for (;;) {
        int rc = file_block(file, unblock_read, 0);
        if (IS_ERR(rc))
            return rc;

        SCOPED_LOCK(tty, tty);
        if (!can_read(tty))
            continue;

        size_t nread = 0;
        while (count) {
            struct attr_char ac;
            ssize_t n = ring_buf_read(tty->input_buf, &ac, sizeof(ac));
            if (IS_ERR(n))
                return n;
            if (!n)
                break;
            if (ac.ch) {
                if (copy_to_user(user_dest, &ac.ch, sizeof(char)))
                    return -EFAULT;
                ++user_dest;
                ++nread;
                --count;
            }
            if (ac.eol)
                break;
        }
        return nread;
    }
}

static void echo(struct tty* tty, const char* buf, size_t count) {
    if (tty->ops->echo)
        tty->ops->echo(tty, buf, count);
}

static void processed_echo(struct tty* tty, const char* buf, size_t count) {
    const struct ktermios* termios = &tty->termios;
    if (!(termios->c_oflag & OPOST) || !(termios->c_oflag & ONLCR)) {
        echo(tty, buf, count);
        return;
    }
    const char* start = buf;
    while (count) {
        const char* p = memchr(start, '\n', count);
        if (!p) {
            echo(tty, start, count);
            break;
        }
        size_t n = p - start;
        if (n > 0)
            echo(tty, start, n);
        echo(tty, "\r\n", 2);
        start = p + 1;
        count -= n + 1;
    }
}

static ssize_t tty_pwrite(struct file* file, const void* user_buf, size_t count,
                          uint64_t offset) {
    (void)offset;

    const unsigned char* user_src = user_buf;

    // Ensure no page faults occur while spinlock is held
    int rc = vm_populate((void*)user_src, (void*)(user_src + count), VM_READ);
    if (IS_ERR(rc))
        return rc;

    struct tty* tty = tty_from_file(file);
    SCOPED_LOCK(tty, tty);

    char buf[256];
    size_t nwritten = 0;
    while (nwritten < count) {
        size_t to_write = MIN(count - nwritten, sizeof(buf));
        if (copy_from_user(buf, user_src, to_write))
            return -EFAULT;
        processed_echo(tty, buf, to_write);
        user_src += to_write;
        nwritten += to_write;
    }

    return nwritten;
}

static int tty_ioctl(struct file* file, unsigned cmd, unsigned long arg) {
    struct tty* tty = tty_from_file(file);
    switch (cmd) {
    case TIOCGPGRP: {
        pid_t pgid;
        {
            SCOPED_LOCK(tty, tty);
            pgid = tty->pgid;
        }
        if (copy_to_user((void*)arg, &pgid, sizeof(pid_t)))
            return -EFAULT;
        break;
    }
    case TIOCSPGRP: {
        pid_t pgid;
        if (copy_from_user(&pgid, (const void*)arg, sizeof(pid_t)))
            return -EFAULT;
        SCOPED_LOCK(tty, tty);
        tty->pgid = pgid;
        break;
    }
    case TCGETS:
    case TCGETS2: {
        struct ktermios termios;
        {
            SCOPED_LOCK(tty, tty);
            termios = tty->termios;
        }
        size_t size = cmd == TCGETS ? sizeof(struct linux_termios)
                                    : sizeof(struct linux_termios2);
        if (copy_to_user((void*)arg, &termios, size))
            return -EFAULT;
        break;
    }
    case TCSETS:
    case TCSETSW:
    case TCSETSF:
    case TCSETS2:
    case TCSETSW2:
    case TCSETSF2: {
        size_t size = (cmd == TCSETS || cmd == TCSETSW || cmd == TCSETSF)
                          ? sizeof(struct linux_termios)
                          : sizeof(struct linux_termios2);
        struct ktermios termios;
        if (copy_from_user(&termios, (const void*)arg, size))
            return -EFAULT;
        SCOPED_LOCK(tty, tty);
        memcpy(&tty->termios, &termios, size);
        if (cmd == TCSETSF || cmd == TCSETSF2) {
            tty->line_len = 0;
            ring_buf_clear(tty->input_buf);
        }
        break;
    }
    case TIOCGWINSZ: {
        struct winsize winsize;
        {
            SCOPED_LOCK(tty, tty);
            winsize = (struct winsize){
                .ws_col = tty->num_columns,
                .ws_row = tty->num_rows,
                .ws_xpixel = 0,
                .ws_ypixel = 0,
            };
        }
        if (copy_to_user((void*)arg, &winsize, sizeof(struct winsize)))
            return -EFAULT;
        break;
    }
    case TIOCSWINSZ: {
        struct winsize winsize;
        if (copy_from_user(&winsize, (const void*)arg, sizeof(struct winsize)))
            return -EFAULT;
        SCOPED_LOCK(tty, tty);
        tty->num_columns = winsize.ws_col;
        tty->num_rows = winsize.ws_row;
        break;
    }
    default:
        if (tty->ops->ioctl)
            return tty->ops->ioctl(tty, file, cmd, arg);
        return -ENOTTY;
    }
    return 0;
}

static short tty_poll(struct file* file, short events) {
    short revents = 0;
    if (events & POLLIN) {
        struct tty* tty = tty_from_file(file);
        SCOPED_LOCK(tty, tty);
        if (can_read(tty))
            revents |= POLLIN;
    }
    if (events & POLLOUT)
        revents |= POLLOUT;
    return revents;
}

const struct file_ops tty_fops = {
    .open = tty_open,
    .pread = tty_pread,
    .pwrite = tty_pwrite,
    .ioctl = tty_ioctl,
    .poll = tty_poll,
};

static bool do_backspace(struct tty* tty) {
    if (tty->line_len) {
        --tty->line_len;
        echo(tty, "\b \b", 3);
        return true;
    }
    return false;
}

static void append_char(struct tty* tty, char ch, bool eol) {
    if (tty->line_len >= sizeof(tty->line_buf))
        return;
    tty->line_buf[tty->line_len++] = (struct attr_char){.ch = ch, .eol = eol};
}

static void commit_line(struct tty* tty) {
    if (!tty->line_len)
        return;
    ring_buf_write_evicting_oldest(tty->input_buf, tty->line_buf,
                                   tty->line_len * sizeof(struct attr_char));
    tty->line_len = 0;
}

NODISCARD static int on_char(struct tty* tty, char ch) {
    struct ktermios* termios = &tty->termios;

    if (termios->c_iflag & ISTRIP)
        ch &= 0x7f;

    if (termios->c_lflag & ISIG) {
        if ((cc_t)ch == termios->c_cc[VINTR])
            return signal_send_to_thread_groups(tty->pgid, 0, SIGINT);
        if ((cc_t)ch == termios->c_cc[VQUIT])
            return signal_send_to_thread_groups(tty->pgid, 0, SIGQUIT);
        if ((cc_t)ch == termios->c_cc[VSUSP])
            return signal_send_to_thread_groups(tty->pgid, 0, SIGTSTP);
    }

    if (ch == '\r' && (termios->c_iflag & ICRNL))
        ch = '\n';
    else if (ch == '\n' && (termios->c_iflag & INLCR))
        ch = '\r';

    if (!(termios->c_lflag & ICANON)) {
        struct attr_char ac = {.ch = ch, .eol = false};
        ring_buf_write_evicting_oldest(tty->input_buf, &ac, sizeof(ac));
        if (termios->c_lflag & ECHO)
            processed_echo(tty, &ch, 1);
        return 0;
    }

    if ((cc_t)ch == termios->c_cc[VKILL] && (termios->c_lflag & ECHOK)) {
        while (do_backspace(tty))
            ;
        return 0;
    }
    if ((cc_t)ch == termios->c_cc[VERASE] && (termios->c_lflag & ECHOE)) {
        do_backspace(tty);
        return 0;
    }
    if ((cc_t)ch == termios->c_cc[VEOL]) {
        commit_line(tty);
        return 0;
    }
    if ((cc_t)ch == termios->c_cc[VEOF]) {
        append_char(tty, 0, true);
        commit_line(tty);
        return 0;
    }
    if (ch == '\n') {
        if (termios->c_lflag & (ECHO | ECHONL))
            processed_echo(tty, "\n", 1);
        append_char(tty, '\n', true);
        commit_line(tty);
        return 0;
    }
    if (!isprint(ch)) {
        if (termios->c_lflag & ECHO)
            processed_echo(tty, "^", 1);
        append_char(tty, '^', false);
        ch |= 0x40;
    }
    if (termios->c_lflag & ECHO)
        processed_echo(tty, &ch, 1);
    append_char(tty, ch, false);
    return 0;
}

ssize_t tty_emit(struct tty* tty, const char* buf, size_t count) {
    SCOPED_LOCK(tty, tty);
    for (size_t i = 0; i < count; ++i) {
        int ret = on_char(tty, buf[i]);
        if (IS_ERR(ret))
            return ret;
    }
    return count;
}
