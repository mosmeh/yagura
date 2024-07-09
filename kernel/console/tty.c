#include "console_private.h"
#include <common/string.h>
#include <kernel/api/signum.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/api/termios.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/safe_string.h>

static bool can_read(struct tty* tty) {
    return !ring_buf_is_empty(&tty->input_buf);
}

static bool unblock_read(file_description* desc) {
    struct tty* tty = (struct tty*)desc->inode;
    return can_read(tty);
}

static ssize_t tty_read(file_description* desc, void* buf, size_t count) {
    struct tty* tty = (struct tty*)desc->inode;

    bool int_flag;
    for (;;) {
        int rc = file_description_block(desc, unblock_read, 0);
        if (IS_ERR(rc))
            return rc;

        int_flag = push_cli();
        if (can_read(tty))
            break;
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

    pop_cli(int_flag);
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

static ssize_t tty_write(file_description* desc, const void* buf,
                         size_t count) {
    struct tty* tty = (struct tty*)desc->inode;
    bool int_flag = push_cli();
    processed_echo(tty, buf, count);
    pop_cli(int_flag);
    return count;
}

static int tty_ioctl(file_description* desc, int request, void* user_argp) {
    struct tty* tty = (struct tty*)desc->inode;
    struct termios* termios = &tty->termios;
    int ret = 0;
    bool int_flag = push_cli();
    switch (request) {
    case TIOCGPGRP:
        if (!copy_to_user(user_argp, &tty->pgid, sizeof(pid_t))) {
            ret = -EFAULT;
            goto done;
        }
        break;
    case TIOCSPGRP:
        if (!copy_from_user(&tty->pgid, user_argp, sizeof(pid_t))) {
            ret = -EFAULT;
            goto done;
        }
        break;
    case TCGETS:
        if (!copy_to_user(user_argp, termios, sizeof(struct termios))) {
            ret = -EFAULT;
            goto done;
        }
        break;
    case TCSETS:
    case TCSETSW:
    case TCSETSF:
        if (!copy_from_user(termios, user_argp, sizeof(struct termios))) {
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
        if (!copy_to_user(user_argp, &winsize, sizeof(struct winsize))) {
            ret = -EFAULT;
            goto done;
        }
        break;
    }
    case TIOCSWINSZ: {
        struct winsize winsize;
        if (!copy_from_user(&winsize, user_argp, sizeof(struct winsize))) {
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
    pop_cli(int_flag);
    return ret;
}

static short tty_poll(file_description* desc, short events) {
    struct tty* tty = (struct tty*)desc->inode;
    short revents = 0;
    if (events & POLLIN) {
        bool int_flag = push_cli();
        if (can_read(tty))
            revents |= POLLIN;
        pop_cli(int_flag);
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

    ASSERT(PAGE_SIZE % sizeof(struct attr_char) == 0);
    int rc = ring_buf_init(&tty->input_buf, PAGE_SIZE);
    if (IS_ERR(rc))
        return rc;

    struct inode* inode = &tty->inode;
    static struct file_ops fops = {
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
            return process_send_signal_to_group(tty->pgid, SIGINT);
        if ((cc_t)ch == termios->c_cc[VQUIT])
            return process_send_signal_to_group(tty->pgid, SIGQUIT);
        if ((cc_t)ch == termios->c_cc[VSUSP])
            return process_send_signal_to_group(tty->pgid, SIGTSTP);
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
    bool int_flag = push_cli();
    int ret = 0;
    for (size_t i = 0; i < count; ++i) {
        ret = on_char(tty, buf[i]);
        if (IS_ERR(ret))
            break;
    }
    pop_cli(int_flag);
    if (IS_ERR(ret))
        return ret;
    return count;
}

void tty_set_echo(struct tty* tty, tty_echo_fn echo, void* ctx) {
    bool int_flag = push_cli();
    tty->echo = echo;
    tty->echo_ctx = ctx;
    pop_cli(int_flag);
}

void tty_set_size(struct tty* tty, size_t num_columns, size_t num_rows) {
    bool int_flag = push_cli();
    tty->num_columns = num_columns;
    tty->num_rows = num_rows;
    pop_cli(int_flag);
}
