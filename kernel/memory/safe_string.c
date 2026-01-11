#include "private.h"
#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>
#include <kernel/system.h>

NOINLINE int safe_memcpy(void* dest, const void* src, size_t n) {
    if (!dest || !src)
        return -EFAULT;

    size_t remainder;
    __asm__ volatile(".globl safe_memcpy_copy\n"
                     "safe_memcpy_copy:\n"
                     "rep movsb\n"
                     ".globl safe_memcpy_on_fault\n"
                     "safe_memcpy_on_fault:"
                     : "=c"(remainder)
                     : "S"(src), "D"(dest), "c"(n)
                     : "memory");
    return remainder == 0 ? 0 : -EFAULT;
}

NOINLINE int safe_memset(void* s, unsigned char c, size_t n) {
    if (!s)
        return -EFAULT;

    size_t remainder;
    __asm__ volatile(".globl safe_memset_write\n"
                     "safe_memset_write:\n"
                     "rep stosb\n"
                     ".globl safe_memset_on_fault\n"
                     "safe_memset_on_fault:"
                     : "=c"(remainder)
                     : "D"(s), "a"(c), "c"(n)
                     : "memory");
    return remainder == 0 ? 0 : -EFAULT;
}

NOINLINE ssize_t safe_strnlen(const char* str, size_t n) {
    if (!str)
        return -EFAULT;

    ssize_t count = 0;
    __asm__ volatile("1:\n"
                     "test %%edx, %%edx\n"
                     "je 2f\n"
                     "dec %%edx\n"
                     ".globl safe_strnlen_read\n"
                     "safe_strnlen_read:\n"
                     "cmpb $0, (%%ebx, %%ecx)\n"
                     "je 2f\n"
                     "inc %%ecx\n"
                     "jmp 1b\n"
                     ".globl safe_strnlen_on_fault\n"
                     "safe_strnlen_on_fault:\n"
                     "mov $-1, %%ecx\n"
                     "2:"
                     : "=c"(count)
                     : "b"(str), "c"(count), "d"(n));
    if (count < 0)
        return -EFAULT;

    return count;
}

NOINLINE ssize_t safe_strncpy(char* dest, const char* src, size_t n) {
    if (!dest || !src)
        return -EFAULT;
    if (n == 0)
        return 0;

    ssize_t num_copied = 0;
    __asm__ volatile("1:\n"
                     ".globl safe_strncpy_read\n"
                     "safe_strncpy_read:\n"
                     "mov (%%esi, %%ecx), %%bl\n"
                     "test %%bl, %%bl\n"
                     "je 2f\n"
                     ".globl safe_strncpy_write\n"
                     "safe_strncpy_write:\n"
                     "mov %%bl, (%%edi, %%ecx)\n"
                     "inc %%ecx\n"
                     "cmp %%ecx, %%eax\n"
                     "jne 1b\n"
                     "jmp 2f\n"
                     ".globl safe_strncpy_on_fault\n"
                     "safe_strncpy_on_fault:\n"
                     "mov $-1, %%ecx\n"
                     "2:"
                     : "=c"(num_copied)
                     : "D"(dest), "S"(src), "a"(n), "c"(0)
                     : "ebx", "memory");
    if (num_copied < 0)
        return -EFAULT;

    ssize_t rc = safe_memset(dest + num_copied, 0, n - num_copied);
    if (IS_ERR(rc))
        return rc;

    return num_copied;
}

int copy_from_user(void* to, const void* user_from, size_t n) {
    ASSERT(is_kernel_address(to));
    if (is_kernel_range(to, n) && is_user_range(user_from, n))
        return safe_memcpy(to, user_from, n);
    return -EFAULT;
}

int copy_to_user(void* user_to, const void* from, size_t n) {
    ASSERT(is_kernel_address(from));
    if (is_user_range(user_to, n) && is_kernel_range(from, n))
        return safe_memcpy(user_to, from, n);
    return -EFAULT;
}

int clear_user(void* user_to, size_t n) {
    if (is_user_range(user_to, n))
        return safe_memset(user_to, 0, n);
    return -EFAULT;
}

ssize_t strnlen_user(const char* user_str, size_t n) {
    if (!is_user_address(user_str))
        return -EFAULT;
    ssize_t len = safe_strnlen(user_str, n);
    if (IS_ERR(len))
        return len;
    if (!is_user_range(user_str, len))
        return -EFAULT;
    return len;
}

ssize_t strncpy_from_user(char* dest, const char* user_src, size_t n) {
    ASSERT(is_kernel_address(dest));
    if (!is_kernel_range(dest, n) || !is_user_address(user_src))
        return -EFAULT;
    ssize_t len = safe_strncpy(dest, user_src, n);
    if (IS_ERR(len))
        return len;
    if (!is_user_range(user_src, len))
        return -EFAULT;
    return len;
}

ssize_t copy_pathname_from_user(char dest[static PATH_MAX],
                                const char* user_src) {
    ssize_t len = strncpy_from_user(dest, user_src, PATH_MAX);
    if (IS_ERR(len))
        return len;
    if (len >= PATH_MAX)
        return -ENAMETOOLONG;
    return len;
}

extern char safe_memcpy_copy[];
extern char safe_memcpy_on_fault[];

extern char safe_memset_write[];
extern char safe_memset_on_fault[];

extern char safe_strnlen_read[];
extern char safe_strnlen_on_fault[];

extern char safe_strncpy_read[];
extern char safe_strncpy_write[];
extern char safe_strncpy_on_fault[];

bool safe_string_handle_page_fault(struct registers* regs) {
    if (regs->error_code & X86_PF_USER) {
        // safe_string functions should have been called from kernel mode
        return false;
    }
    if (regs->eip == (uintptr_t)safe_memcpy_copy) {
        regs->eip = (uintptr_t)safe_memcpy_on_fault;
        return true;
    }
    if (regs->eip == (uintptr_t)safe_memset_write) {
        regs->eip = (uintptr_t)safe_memset_on_fault;
        return true;
    }
    if (regs->eip == (uintptr_t)safe_strnlen_read) {
        regs->eip = (uintptr_t)safe_strnlen_on_fault;
        return true;
    }
    if (regs->eip == (uintptr_t)safe_strncpy_read ||
        regs->eip == (uintptr_t)safe_strncpy_write) {
        regs->eip = (uintptr_t)safe_strncpy_on_fault;
        return true;
    }
    return false;
}
