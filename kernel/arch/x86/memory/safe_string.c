#include <kernel/api/err.h>
#include <kernel/arch/x86/memory/page_fault.h>
#include <kernel/arch/x86/task/context.h>
#include <kernel/cpu.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>

static bool is_canonical_addr(const void* addr) {
#ifdef ARCH_I386
    (void)addr;
    return true;
#endif
#ifdef ARCH_X86_64
    uint8_t msb = cpu_get_bsp()->arch.virt_addr_bits - 1;
    uintptr_t upper_bits = (uintptr_t)addr >> msb;
    return upper_bits == 0 || upper_bits == ((uintptr_t)-1 >> msb);
#endif
}

static void begin_user_access(void) {
    if (cpu_has_feature(cpu_get_bsp(), X86_FEATURE_SMAP))
        __asm__ volatile("stac" ::: "memory");
}

static void end_user_access(void) {
    if (cpu_has_feature(cpu_get_bsp(), X86_FEATURE_SMAP))
        __asm__ volatile("clac" ::: "memory");
}

NOINLINE int safe_memcpy(void* dest, const void* src, size_t n) {
    if (!dest || !src || !is_canonical_addr(dest) || !is_canonical_addr(src))
        return -EFAULT;

    size_t remainder;

    begin_user_access();
    __asm__ volatile(".globl safe_memcpy_copy\n"
                     "safe_memcpy_copy:\n"
                     "rep movsb\n"
                     ".globl safe_memcpy_on_fault\n"
                     "safe_memcpy_on_fault:\n"
                     : "=c"(remainder)
                     : "S"(src), "D"(dest), "c"(n)
                     : "memory");
    end_user_access();

    return remainder == 0 ? 0 : -EFAULT;
}

NOINLINE int safe_memset(void* s, unsigned char c, size_t n) {
    if (!s || !is_canonical_addr(s))
        return -EFAULT;

    size_t remainder;

    begin_user_access();
    __asm__ volatile(".globl safe_memset_write\n"
                     "safe_memset_write:\n"
                     "rep stosb\n"
                     ".globl safe_memset_on_fault\n"
                     "safe_memset_on_fault:\n"
                     : "=c"(remainder)
                     : "D"(s), "a"(c), "c"(n)
                     : "memory");
    end_user_access();

    return remainder == 0 ? 0 : -EFAULT;
}

NOINLINE ssize_t safe_strnlen(const char* str, size_t n) {
    if (!str || !is_canonical_addr(str))
        return -EFAULT;

    ssize_t count = 0;

    begin_user_access();
    __asm__ volatile("1:\n"
                     "test %[n], %[n]\n"
                     "je 2f\n"
                     "dec %[n]\n"
                     ".globl safe_strnlen_read\n"
                     "safe_strnlen_read:\n"
                     "cmpb $0, (%[str], %[count])\n"
                     "je 2f\n"
                     "inc %[count]\n"
                     "jmp 1b\n"
                     ".globl safe_strnlen_on_fault\n"
                     "safe_strnlen_on_fault:\n"
                     "mov $-1, %[count]\n"
                     "2:\n"
                     : "=c"(count)
                     : [str] "b"(str), [count] "c"(count), [n] "d"(n));
    end_user_access();

    if (count < 0)
        return -EFAULT;

    return count;
}

NOINLINE ssize_t safe_strncpy(char* dest, const char* src, size_t n) {
    if (!dest || !src || !is_canonical_addr(dest) || !is_canonical_addr(src))
        return -EFAULT;
    if (n == 0)
        return 0;

    ssize_t count = 0;

    begin_user_access();
    __asm__ volatile(
        "1:\n"
        ".globl safe_strncpy_read\n"
        "safe_strncpy_read:\n"
        "mov (%[src], %[count]), %%bl\n"
        "test %%bl, %%bl\n"
        "je 2f\n"
        ".globl safe_strncpy_write\n"
        "safe_strncpy_write:\n"
        "mov %%bl, (%[dest], %[count])\n"
        "inc %[count]\n"
        "cmp %[count], %[n]\n"
        "jne 1b\n"
        "jmp 2f\n"
        ".globl safe_strncpy_on_fault\n"
        "safe_strncpy_on_fault:\n"
        "mov $-1, %[count]\n"
        "2:\n"
        : "=c"(count)
        : [dest] "D"(dest), [src] "S"(src), [n] "a"(n), [count] "c"(0L)
        : "ebx", "memory");
    end_user_access();

    if (count < 0)
        return -EFAULT;

    int rc = safe_memset(dest + count, 0, n - count);
    if (IS_ERR(rc))
        return rc;

    return count;
}

extern unsigned char safe_memcpy_copy[];
extern unsigned char safe_memcpy_on_fault[];

extern unsigned char safe_memset_write[];
extern unsigned char safe_memset_on_fault[];

extern unsigned char safe_strnlen_read[];
extern unsigned char safe_strnlen_on_fault[];

extern unsigned char safe_strncpy_read[];
extern unsigned char safe_strncpy_write[];
extern unsigned char safe_strncpy_on_fault[];

bool safe_string_handle_page_fault(struct registers* regs,
                                   unsigned long error_code) {
    if (error_code & X86_PF_USER) {
        // safe_string functions should have been called from kernel mode
        return false;
    }
    if (regs->ip == (uintptr_t)safe_memcpy_copy) {
        regs->ip = (uintptr_t)safe_memcpy_on_fault;
        return true;
    }
    if (regs->ip == (uintptr_t)safe_memset_write) {
        regs->ip = (uintptr_t)safe_memset_on_fault;
        return true;
    }
    if (regs->ip == (uintptr_t)safe_strnlen_read) {
        regs->ip = (uintptr_t)safe_strnlen_on_fault;
        return true;
    }
    if (regs->ip == (uintptr_t)safe_strncpy_read ||
        regs->ip == (uintptr_t)safe_strncpy_write) {
        regs->ip = (uintptr_t)safe_strncpy_on_fault;
        return true;
    }
    return false;
}
