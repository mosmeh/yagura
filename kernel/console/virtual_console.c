#include "console_private.h"
#include <common/string.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/drivers/hid/hid.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/ring_buf.h>
#include <kernel/safe_string.h>

static ring_buf input_buf;

static void input_buf_write_str(const char* s) {
    bool int_flag = push_cli();
    ring_buf_write_evicting_oldest(&input_buf, s, strlen(s));
    pop_cli(int_flag);
}

static pid_t pgid;

static void on_key_event(const key_event* event) {
    if (!event->pressed)
        return;
    switch (event->keycode) {
    case KEYCODE_UP:
        input_buf_write_str("\x1b[A");
        return;
    case KEYCODE_DOWN:
        input_buf_write_str("\x1b[B");
        return;
    case KEYCODE_RIGHT:
        input_buf_write_str("\x1b[C");
        return;
    case KEYCODE_LEFT:
        input_buf_write_str("\x1b[D");
        return;
    case KEYCODE_HOME:
        input_buf_write_str("\x1b[H");
        return;
    case KEYCODE_END:
        input_buf_write_str("\x1b[F");
        return;
    case KEYCODE_DELETE:
        input_buf_write_str("\x1b[3~");
        return;
    default:
        break;
    }

    if (!event->key)
        return;
    char key = event->key;
    if (event->modifiers & KEY_MODIFIER_CTRL) {
        if ('a' <= key && key <= 'z')
            key -= '`';
        else if (key == '\\')
            key = 0x1c;
    }

    tty_maybe_send_signal(pgid, key);

    bool int_flag = push_cli();
    ring_buf_write_evicting_oldest(&input_buf, &key, 1);
    pop_cli(int_flag);
}

static bool can_read(void) {
    bool int_flag = push_cli();
    bool ret = !ring_buf_is_empty(&input_buf);
    pop_cli(int_flag);
    return ret;
}

static bool read_should_unblock(file_description* desc) {
    (void)desc;
    return can_read();
}

static ssize_t virtual_console_device_read(file_description* desc, void* buffer,
                                           size_t count) {
    for (;;) {
        int rc = file_description_block(desc, read_should_unblock);
        if (IS_ERR(rc))
            return rc;

        bool int_flag = push_cli();
        if (ring_buf_is_empty(&input_buf)) {
            pop_cli(int_flag);
            continue;
        }

        ssize_t nread = ring_buf_read(&input_buf, buffer, count);
        pop_cli(int_flag);
        return nread;
    }
}

static mutex lock;
static struct vt* vt;
static struct screen* screen;

static ssize_t virtual_console_device_write(file_description* desc,
                                            const void* buffer, size_t count) {
    (void)desc;
    const char* chars = (char*)buffer;
    mutex_lock(&lock);

    for (size_t i = 0; i < count; ++i)
        vt_on_char(vt, chars[i]);
    vt_flush(vt);

    mutex_unlock(&lock);
    return count;
}

static int virtual_console_device_ioctl(file_description* desc, int request,
                                        void* user_argp) {
    (void)desc;
    switch (request) {
    case TIOCGPGRP:
        if (!copy_to_user(user_argp, &pgid, sizeof(pid_t)))
            return -EFAULT;
        return 0;
    case TIOCSPGRP: {
        pid_t new_pgid;
        if (!copy_from_user(&new_pgid, user_argp, sizeof(pid_t)))
            return -EFAULT;
        if (new_pgid < 0)
            return -EINVAL;
        pgid = new_pgid;
        return 0;
    }
    case TIOCGWINSZ: {
        size_t num_columns;
        size_t num_rows;
        screen->get_size(screen, &num_columns, &num_rows);
        struct winsize winsize = {.ws_col = num_columns,
                                  .ws_row = num_rows,
                                  .ws_xpixel = 0,
                                  .ws_ypixel = 0};
        if (!copy_to_user(user_argp, &winsize, sizeof(struct winsize)))
            return -EFAULT;
        return 0;
    }
    }
    return -EINVAL;
}

static short virtual_console_device_poll(file_description* desc, short events) {
    (void)desc;
    short revents = 0;
    if ((events & POLLIN) && can_read())
        revents |= POLLIN;
    if (events & POLLOUT)
        revents |= POLLOUT;
    return revents;
}

static struct inode* virtual_console_device_get(void) {
    static file_ops fops = {.read = virtual_console_device_read,
                            .write = virtual_console_device_write,
                            .ioctl = virtual_console_device_ioctl,
                            .poll = virtual_console_device_poll};
    static struct inode inode = {
        .fops = &fops, .mode = S_IFCHR, .rdev = makedev(5, 0), .ref_count = 1};
    return &inode;
}

void virtual_console_init(struct screen* s) {
    screen = s;
    vt = vt_create(screen);
    ASSERT(vt);

    ASSERT_OK(ring_buf_init(&input_buf));
    ps2_set_key_event_handler(on_key_event);

    ASSERT_OK(vfs_register_device("tty", virtual_console_device_get()));
}
