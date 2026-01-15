#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>

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
    ASSERT(user_str < (const char*)USER_VIRT_END);
    size_t limit = (const char*)USER_VIRT_END - user_str;
    ssize_t len = safe_strnlen(user_str, MIN(n, limit));
    if (IS_ERR(len))
        return len;
    if ((size_t)len == limit && n > limit)
        return -EFAULT;
    return len;
}

ssize_t strncpy_from_user(char* dest, const char* user_src, size_t n) {
    ASSERT(is_kernel_address(dest));
    if (!is_kernel_range(dest, n) || !is_user_address(user_src))
        return -EFAULT;
    ASSERT(user_src < (const char*)USER_VIRT_END);
    size_t limit = (const char*)USER_VIRT_END - user_src;
    ssize_t len = safe_strncpy(dest, user_src, MIN(n, limit));
    if (IS_ERR(len))
        return len;
    if ((size_t)len == limit && n > limit)
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
