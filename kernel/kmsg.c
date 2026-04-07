#include <common/stdarg.h>
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/errno.h>
#include <kernel/console/console.h>
#include <kernel/kmsg.h>
#include <kernel/lock/spinlock.h>
#include <kernel/time.h>

int kprint(const char* str) {
    size_t len = strlen(str);
    kmsg_write(str, len);
    return len;
}

int kprintf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = kvprintf(format, args);
    va_end(args);
    return ret;
}

int kvprintf(const char* format, va_list args) {
    char buf[1024];
    int len = vsnprintf(buf, sizeof(buf), format, args);
    if (len < 0)
        return -EINVAL;
    // Just truncate the message if it's too long, since we don't want
    // kprintf to fail.
    size_t count = (size_t)len < sizeof(buf) ? (size_t)len : sizeof(buf) - 1;
    kmsg_write(buf, count);
    return len;
}

#define RING_BUF_LEN (KMSG_BUF_CAPACITY + 1) // +1 to distinguish full vs empty

static char ring_buf[RING_BUF_LEN];
static size_t read_index = 0;
static size_t write_index = 0;
static struct spinlock lock;

size_t kmsg_read(char* buf, size_t count, size_t offset) {
    if (offset >= KMSG_BUF_CAPACITY)
        return 0;

    SCOPED_LOCK(spinlock, &lock);

    size_t size = kmsg_size();
    if (offset >= size)
        return 0;

    size_t to_read = MIN(count, size - offset);
    for (size_t i = 0; i < to_read; ++i)
        buf[i] = ring_buf[(read_index + offset + i) % RING_BUF_LEN];
    return to_read;
}

static void write(const char* buf, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        ring_buf[write_index] = buf[i];
        write_index = (write_index + 1) % RING_BUF_LEN;
        if (write_index == read_index)
            read_index = (read_index + 1) % RING_BUF_LEN;
    }
    system_console_echo(buf, count);
}

static void log(unsigned long timestamp, const char* buf, size_t count) {
    unsigned long secs = timestamp / CLK_TCK;
    // Map [0, CLK_TCK) to [0, 1000)
    unsigned long frac = (timestamp % CLK_TCK) * 1000 / CLK_TCK;

    char timestamp_buf[32];
    int len = sprintf(timestamp_buf, "[%5lu.%03lu] ", secs, frac);
    write(timestamp_buf, len);
    write(buf, count);
}

void kmsg_write(const char* buf, size_t count) {
    unsigned long timestamp = uptime;
    const char* buf_end = buf + count;

    SCOPED_LOCK(spinlock, &lock);
    for (const char* p = buf; p < buf_end;) {
        const char* line_end = memchr(p, '\n', buf_end - p);
        if (!line_end) {
            log(timestamp, p, buf_end - p);
            write("\n", 1);
            break;
        }
        log(timestamp, p, line_end - p + 1);
        p = line_end + 1;
    }
}

size_t kmsg_size(void) {
    SCOPED_LOCK(spinlock, &lock);
    return (write_index + RING_BUF_LEN - read_index) % RING_BUF_LEN;
}

void kmsg_clear(void) {
    SCOPED_LOCK(spinlock, &lock);
    read_index = write_index = 0;
}
