#include "api/errno.h"
#include "cpu.h"
#include "drivers/rtc.h"
#include "kmsg.h"
#include <common/extra.h>
#include <stdalign.h>

static bool use_rdrand = false;

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
static inline bool rdrand(uint32_t* v) {
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
    uint32_t prev = UINT32_MAX;
    unsigned fails = 0;
    for (unsigned i = 0; i < 8; ++i) {
        uint32_t v = 0;
        if (!rdrand(&v))
            return false;
        if (v == prev)
            ++fails;
        else
            prev = v;
    }
    return fails <= 2;
}

// https://prng.di.unimi.it/splitmix64.c
static uint64_t splitmix64_next(uint64_t* x) {
    uint64_t z = (*x += 0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

// https://prng.di.unimi.it/xoshiro128plusplus.c

static inline uint32_t rotl(const uint32_t x, int k) {
    return (x << k) | (x >> (32 - k));
}

static uint32_t s[4];

static uint32_t xoshiro128plusplus_next(void) {
    const uint32_t result = rotl(s[0] + s[3], 7) + s[0];
    const uint32_t t = s[1] << 9;

    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];

    s[2] ^= t;

    s[3] = rotl(s[3], 11);
    return result;
}

void random_init(void) {
    if (rdrand_init()) {
        use_rdrand = true;
        return;
    }
    kprint(
        "random: RDRAND is unavailable or unreliable. Falling back to PRNG.\n");

    uint64_t seed = rtc_now();
    uint64_t a = splitmix64_next(&seed);
    uint64_t b = splitmix64_next(&seed);
    s[0] = a & 0xffffffff;
    s[1] = a >> 32;
    s[2] = b & 0xffffffff;
    s[3] = b >> 32;
}

static bool next(uint32_t* v) {
    if (use_rdrand)
        return rdrand(v);

    *v = xoshiro128plusplus_next();
    return true;
}

static bool fill_remainder(unsigned char* buffer, uint8_t count) {
    uint32_t v = 0;
    if (!next(&v))
        return false;
    switch (count) {
    case 3:
        *buffer++ = v & 0xff;
        // falls through
    case 2:
        *buffer++ = (v >> 8) & 0xff;
        // falls through
    case 1:
        *buffer = (v >> 16) & 0xff;
    }
    return true;
}

ssize_t random_get(void* buffer, size_t count) {
    unsigned char* prefix = buffer;
    unsigned char* aligned =
        (unsigned char*)round_up((uintptr_t)buffer, alignof(uint32_t));
    unsigned char* end = prefix + count;
    unsigned char* suffix =
        (unsigned char*)round_down((uintptr_t)end, alignof(uint32_t));

    if (prefix < aligned) {
        if (!fill_remainder(prefix, aligned - prefix))
            return -EIO;
    }

    for (unsigned char* p = aligned; p < suffix; p += alignof(uint32_t)) {
        uint32_t v = 0;
        if (!next(&v))
            return -EIO;
        p[0] = v & 0xff;
        p[1] = (v >> 8) & 0xff;
        p[2] = (v >> 16) & 0xff;
        p[3] = (v >> 24) & 0xff;
    }

    if (suffix < end) {
        if (!fill_remainder(suffix, end - suffix))
            return -EIO;
    }

    return count;
}
