#include "private.h"
#include <common/string.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/api/termios.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/task.h>

static bool can_read(struct tty* tty) {
    return !ring_buf_is_empty(&tty->input_buf);
}

static bool unblock_read(struct file* file) {
    struct tty* tty = (struct tty*)file->inode;
    return can_read(tty);
}

static ssize_t tty_read(struct file* file, void* buf, size_t count) {
    struct tty* tty = (struct tty*)file->inode;

    for (;;) {
        int rc = file_block(file, unblock_read, 0);
        if (IS_ERR(rc))
            return rc;

        spinlock_lock(&tty->lock);
        if (can_read(tty))
            break;
        spinlock_unlock(&tty->lock);
    }

    ssize_t ret = 0;
    char* dest = buf;
    while (count) {
        struct attr_char ac;
        ssize_t nread = ring_buf_read(&tty->input_buf, &ac, sizeof(ac));
        if (IS_ERR(nread)) {
            ret = nread;
            break;
        }
        if (!nread)
            break;
        if (ac.ch) {
            *dest++ = ac.ch;
            ++ret;
            --count;
        }
        if (ac.eol)
            break;
    }

    spinlock_unlock(&tty->lock);
    return ret;
}

static void echo(struct tty* tty, const char* buf, size_t count) {
    if (tty->echo)
        tty->echo(buf, count, tty->echo_ctx);
}

static void processed_echo(struct tty* tty, const char* buf, size_t count) {
    struct termios* termios = &tty->termios;
    if (!(termios->c_oflag & OPOST)) {
        echo(tty, buf, count);
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        char ch = buf[i];
        if (ch == '\n' && (termios->c_oflag & ONLCR))
            echo(tty, "\r", 1);
        echo(tty, &ch, 1);
    }
}

static ssize_t tty_write(struct file* file, const void* buf, size_t count) {
    struct tty* tty = (struct tty*)file->inode;
    spinlock_lock(&tty->lock);
    processed_echo(tty, buf, count);
    spinlock_unlock(&tty->lock);
    return count;
}

static int tty_ioctl(struct file* file, int request, void* user_argp) {
    struct tty* tty = (struct tty*)file->inode;
    struct termios* termios = &tty->termios;
    int ret = 0;
    spinlock_lock(&tty->lock);
    switch (request) {
    case TIOCGPGRP:
        if (copy_to_user(user_argp, &tty->pgid, sizeof(pid_t))) {
            ret = -EFAULT;
            goto done;
        }
        break;
    case TIOCSPGRP:
        if (copy_from_user(&tty->pgid, user_argp, sizeof(pid_t))) {
            ret = -EFAULT;
            goto done;
        }
        break;
    case TCGETS:
        if (copy_to_user(user_argp, termios, sizeof(struct termios))) {
            ret = -EFAULT;
            goto done;
        }
        break;
    case TCSETS:
    case TCSETSW:
    case TCSETSF:
        if (copy_from_user(termios, user_argp, sizeof(struct termios))) {
            ret = -EFAULT;
            goto done;
        }
        if (request == TCSETSF) {
            tty->line_len = 0;
            ring_buf_clear(&tty->input_buf);
        }
        break;
    case TIOCGWINSZ: {
        struct winsize winsize = {
            .ws_col = tty->num_columns,
            .ws_row = tty->num_rows,
            .ws_xpixel = 0,
            .ws_ypixel = 0,
        };
        if (copy_to_user(user_argp, &winsize, sizeof(struct winsize))) {
            ret = -EFAULT;
            goto done;
        }
        break;
    }
    case TIOCSWINSZ: {
        struct winsize winsize;
        if (copy_from_user(&winsize, user_argp, sizeof(struct winsize))) {
            ret = -EFAULT;
            goto done;
        }
        tty->num_columns = winsize.ws_col;
        tty->num_rows = winsize.ws_row;
        break;
    }
    default:
        ret = -EINVAL;
        break;
    }
done:
    spinlock_unlock(&tty->lock);
    return ret;
}

static short tty_poll(struct file* file, short events) {
    struct tty* tty = (struct tty*)file->inode;
    short revents = 0;
    if (events & POLLIN) {
        spinlock_lock(&tty->lock);
        if (can_read(tty))
            revents |= POLLIN;
        spinlock_unlock(&tty->lock);
    }
    if (events & POLLOUT)
        revents |= POLLOUT;
    return revents;
}

static const struct termios default_termios = {
    .c_iflag = TTYDEF_IFLAG,
    .c_oflag = TTYDEF_OFLAG,
    .c_cflag = TTYDEF_CFLAG,
    .c_lflag = TTYDEF_LFLAG,
    .c_ispeed = TTYDEF_SPEED,
    .c_ospeed = TTYDEF_SPEED,
};

int tty_init(struct tty* tty, uint8_t minor) {
    *tty = (struct tty){
        .termios = default_termios,
        .num_columns = 80,
        .num_rows = 25,
    };
    memcpy(tty->termios.c_cc, ttydefchars, sizeof(tty->termios.c_cc));

    STATIC_ASSERT(PAGE_SIZE % sizeof(struct attr_char) == 0);
    int rc = ring_buf_init(&tty->input_buf, PAGE_SIZE);
    if (IS_ERR(rc))
        return rc;

    struct inode* inode = &tty->inode;
    static const struct file_ops fops = {
        .read = tty_read,
        .write = tty_write,
        .ioctl = tty_ioctl,
        .poll = tty_poll,
    };
    inode->fops = &fops;
    inode->mode = S_IFCHR;
    inode->rdev = makedev(4, minor);
    inode->ref_count = 1;

    return 0;
}

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
    ring_buf_write_evicting_oldest(&tty->input_buf, tty->line_buf,
                                   tty->line_len * sizeof(struct attr_char));
    tty->line_len = 0;
}

NODISCARD static int on_char(struct tty* tty, char ch) {
    struct termios* termios = &tty->termios;

    if (termios->c_lflag & ISTRIP)
        ch &= 0x7f;

    if (termios->c_lflag & ISIG) {
        if ((cc_t)ch == termios->c_cc[VINTR])
            return task_send_signal(tty->pgid, SIGINT,
                                    SIGNAL_DEST_PROCESS_GROUP);
        if ((cc_t)ch == termios->c_cc[VQUIT])
            return task_send_signal(tty->pgid, SIGQUIT,
                                    SIGNAL_DEST_PROCESS_GROUP);
        if ((cc_t)ch == termios->c_cc[VSUSP])
            return task_send_signal(tty->pgid, SIGTSTP,
                                    SIGNAL_DEST_PROCESS_GROUP);
    }

    if (ch == '\r' && (termios->c_iflag & ICRNL))
        ch = '\n';
    else if (ch == '\n' && (termios->c_iflag & INLCR))
        ch = '\r';

    if (!(termios->c_lflag & ICANON)) {
        struct attr_char ac = {.ch = ch, .eol = false};
        ring_buf_write_evicting_oldest(&tty->input_buf, &ac, sizeof(ac));
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
    spinlock_lock(&tty->lock);
    int ret = 0;
    for (size_t i = 0; i < count; ++i) {
        ret = on_char(tty, buf[i]);
        if (IS_ERR(ret))
            break;
    }
    spinlock_unlock(&tty->lock);
    if (IS_ERR(ret))
        return ret;
    return count;
}

void tty_set_echo(struct tty* tty, tty_echo_fn echo, void* ctx) {
    spinlock_lock(&tty->lock);
    tty->echo = echo;
    tty->echo_ctx = ctx;
    spinlock_unlock(&tty->lock);
}

void tty_set_size(struct tty* tty, size_t num_columns, size_t num_rows) {
    spinlock_lock(&tty->lock);
    tty->num_columns = num_columns;
    tty->num_rows = num_rows;
    spinlock_unlock(&tty->lock);
}
