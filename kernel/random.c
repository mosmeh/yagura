#include <common/random.h>
#include <common/string.h>
#include <kernel/arch/system.h>
#include <kernel/cpu.h>
#include <kernel/lock.h>
#include <kernel/memory/safe_string.h>
#include <kernel/time.h>

static bool use_arch_random = false;

static uint32_t s[4];
static struct mutex lock;

void random_init(void) {
    if (arch_random_init()) {
        use_arch_random = true;
        return;
    }

    struct timespec now;
    ASSERT_OK(time_now(CLOCK_REALTIME, &now));
    uint64_t seed = now.tv_sec ^ now.tv_nsec;
    uint64_t a = splitmix64_next(&seed);
    uint64_t b = splitmix64_next(&seed);
    s[0] = a & 0xffffffff;
    s[1] = a >> 32;
    s[2] = b & 0xffffffff;
    s[3] = b >> 32;
}

ssize_t random_get(void* buffer, size_t count) {
    SCOPED_LOCK(mutex, &lock);

    if (use_arch_random)
        return arch_random_get(buffer, count);

    unsigned char* dest = buffer;
    size_t n = 0;
    while (n < count) {
        union {
            uint32_t val;
            unsigned char bytes[sizeof(uint32_t)];
        } u = {
            .val = xoshiro128plusplus_next(s),
        };
        size_t to_copy = MIN(count - n, sizeof(u.bytes));
        memcpy(dest, u.bytes, to_copy);
        dest += to_copy;
        n += to_copy;
    }
    return n;
}

ssize_t random_get_user(void* user_buffer, size_t count) {
    if (count == 0)
        return 0;
    if (!is_user_range(user_buffer, count))
        return -EFAULT;

    unsigned char buf[256];
    unsigned char* user_dest = user_buffer;
    size_t nread = 0;
    while (nread < count) {
        size_t to_read = MIN(count - nread, sizeof(buf));
        ssize_t n = random_get(buf, to_read);
        if (IS_ERR(n))
            return n;
        if (n == 0)
            break;
        if (copy_to_user(user_dest, buf, n))
            return -EFAULT;
        user_dest += n;
        nread += n;
    }
    return nread;
}
