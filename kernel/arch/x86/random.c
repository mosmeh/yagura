#include <common/limits.h>
#include <common/string.h>
#include <kernel/arch/system.h>
#include <kernel/arch/x86/cpu.h>
#include <kernel/cpu.h>
#include <kernel/kmsg.h>

// based on
// https://github.com/torvalds/linux/blob/7a934f4bd7d6f9da84c8812da3ba42ee10f5778e/arch/x86/include/asm/archrandom.h#L20

#ifdef __GCC_ASM_FLAG_OUTPUTS__
#define CC_SET
#define CC_OUT "=@ccc"
#else
#define CC_SET "\nsetc %[cc_out]"
#define CC_OUT [cc_out] "=qm"
#endif

// NOLINTNEXTLINE(readability-non-const-parameter)
static inline bool rdrand(unsigned long* v) {
    bool ok;
    unsigned retry = 10;
    do {
        __asm__ volatile("rdrand %[out]" CC_SET : CC_OUT(ok), [out] "=r"(*v));
        if (ok)
            return true;
    } while (--retry);
    return false;
}

#undef CC_SET
#undef CC_OUT

// based on
// https://github.com/rust-random/getrandom/blob/666b2d4c8352a188da7dbb4a4d6754a6ba2ac3f8/src/rdrand.rs#L46-L101
NODISCARD static bool rdrand_init(void) {
    if (!cpu_has_feature(cpu_get_bsp(), X86_FEATURE_RDRAND))
        return false;

    // is RDRAND reliable?
    unsigned long prev = ULONG_MAX;
    unsigned fails = 0;
    for (unsigned i = 0; i < 8; ++i) {
        unsigned long v = 0;
        if (!rdrand(&v))
            return false;
        if (v == prev)
            ++fails;
        else
            prev = v;
    }
    return fails <= 2;
}

static bool rdrand_available;

bool arch_random_init(void) {
    if (rdrand_init()) {
        rdrand_available = true;
        return true;
    }
    kprint("random: RDRAND is unavailable or unreliable\n");
    return false;
}

ssize_t arch_random_get(void* buffer, size_t count) {
    if (!rdrand_available)
        return -EIO;

    unsigned char* dest = buffer;
    size_t n = 0;
    while (n < count) {
        unsigned long v = 0;
        if (!rdrand(&v)) {
            if (n == 0)
                return -EIO;
            break;
        }

        union {
            unsigned long val;
            unsigned char bytes[sizeof(unsigned long)];
        } u = {.val = v};

        size_t to_copy = MIN(count - n, sizeof(u.bytes));
        memcpy(dest, u.bytes, to_copy);
        dest += to_copy;
        n += to_copy;
    }
    return n;
}
