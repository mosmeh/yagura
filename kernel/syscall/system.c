#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/linux/random.h>
#include <kernel/api/sys/reboot.h>
#include <kernel/api/sys/sysinfo.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/system.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

// There is no support for users and groups in this kernel.
// It behaves as if the user is always root.

long sys_getuid(void) { return sys_getuid16(); }

long sys_getuid16(void) { return 0; }

long sys_geteuid(void) { return sys_geteuid16(); }

long sys_geteuid16(void) { return 0; }

long sys_getgid(void) { return sys_getgid16(); }

long sys_getgid16(void) { return 0; }

long sys_getegid(void) { return sys_getegid16(); }

long sys_getegid16(void) { return 0; }

long sys_getresuid(uid_t* user_ruid, uid_t* user_euid, uid_t* user_suid) {
    uid_t zero = 0;
    if (copy_to_user(user_ruid, &zero, sizeof(uid_t)))
        return -EFAULT;
    if (copy_to_user(user_euid, &zero, sizeof(uid_t)))
        return -EFAULT;
    if (copy_to_user(user_suid, &zero, sizeof(uid_t)))
        return -EFAULT;
    return 0;
}

long sys_getresuid16(linux_old_uid_t* user_ruid, linux_old_uid_t* user_euid,
                     linux_old_uid_t* user_suid) {
    linux_old_uid_t zero = 0;
    if (copy_to_user(user_ruid, &zero, sizeof(linux_old_uid_t)))
        return -EFAULT;
    if (copy_to_user(user_euid, &zero, sizeof(linux_old_uid_t)))
        return -EFAULT;
    if (copy_to_user(user_suid, &zero, sizeof(linux_old_uid_t)))
        return -EFAULT;
    return 0;
}

long sys_getresgid(gid_t* user_rgid, gid_t* user_egid, gid_t* user_sgid) {
    gid_t zero = 0;
    if (copy_to_user(user_rgid, &zero, sizeof(gid_t)))
        return -EFAULT;
    if (copy_to_user(user_egid, &zero, sizeof(gid_t)))
        return -EFAULT;
    if (copy_to_user(user_sgid, &zero, sizeof(gid_t)))
        return -EFAULT;
    return 0;
}

long sys_getresgid16(linux_old_gid_t* user_rgid, linux_old_gid_t* user_egid,
                     linux_old_gid_t* user_sgid) {
    linux_old_gid_t zero = 0;
    if (copy_to_user(user_rgid, &zero, sizeof(linux_old_gid_t)))
        return -EFAULT;
    if (copy_to_user(user_egid, &zero, sizeof(linux_old_gid_t)))
        return -EFAULT;
    if (copy_to_user(user_sgid, &zero, sizeof(linux_old_gid_t)))
        return -EFAULT;
    return 0;
}

// NOLINTNEXTLINE(readability-non-const-parameter)
long sys_getgroups(int size, gid_t* user_list) {
    (void)user_list;
    if (size < 0)
        return -EINVAL;
    return 0;
}

// NOLINTNEXTLINE(readability-non-const-parameter)
long sys_getgroups16(int size, linux_old_gid_t* user_list) {
    (void)user_list;
    if (size < 0)
        return -EINVAL;
    return 0;
}

long sys_reboot(int magic, int magic2, int op, void* user_arg) {
    if ((unsigned)magic != LINUX_REBOOT_MAGIC1)
        return -EINVAL;
    switch (magic2) {
    case LINUX_REBOOT_MAGIC2:
    case LINUX_REBOOT_MAGIC2A:
    case LINUX_REBOOT_MAGIC2B:
    case LINUX_REBOOT_MAGIC2C:
        break;
    default:
        return -EINVAL;
    }

    switch (op) {
    case LINUX_REBOOT_CMD_RESTART:
        reboot(NULL);
    case LINUX_REBOOT_CMD_RESTART2: {
        char arg[256] = {0};
        ssize_t rc = strncpy_from_user(arg, user_arg, sizeof(arg));
        if (IS_ERR(rc))
            return rc;
        arg[sizeof(arg) - 1] = 0;
        reboot(arg);
    }
    case LINUX_REBOOT_CMD_HALT:
        halt();
    case LINUX_REBOOT_CMD_POWER_OFF:
        poweroff();
    default:
        return -EINVAL;
    }
}

long sys_sysinfo(struct sysinfo* user_info) {
    struct memory_stats memory_stats;
    memory_get_stats(&memory_stats);

    size_t num_procs = 0;
    {
        SCOPED_LOCK(spinlock, &tasks_lock);
        for (struct task* task = tasks; task; task = task->tasks_next)
            ++num_procs;
    }

    struct sysinfo info = {
        .uptime = uptime / CLK_TCK,
        .totalram = memory_stats.total_kibibytes,
        .freeram = memory_stats.free_kibibytes,
        .procs = num_procs,
        .mem_unit = 1024,
    };
    if (copy_to_user(user_info, &info, sizeof(struct sysinfo)))
        return -EFAULT;
    return 0;
}

long sys_olduname(struct linux_oldold_utsname* user_buf) {
    struct utsname utsname;
    utsname_get(&utsname);
    struct linux_oldold_utsname buf = {0};
    strlcpy(buf.sysname, utsname.sysname, sizeof(buf.sysname));
    strlcpy(buf.nodename, utsname.nodename, sizeof(buf.nodename));
    strlcpy(buf.release, utsname.release, sizeof(buf.release));
    strlcpy(buf.version, utsname.version, sizeof(buf.version));
    strlcpy(buf.machine, utsname.machine, sizeof(buf.machine));
    if (copy_to_user(user_buf, &buf, sizeof(struct linux_oldold_utsname)))
        return -EFAULT;
    return 0;
}

long sys_uname(struct linux_old_utsname* user_buf) {
    struct utsname utsname;
    utsname_get(&utsname);
    struct linux_old_utsname buf = {0};
    strlcpy(buf.sysname, utsname.sysname, sizeof(buf.sysname));
    strlcpy(buf.nodename, utsname.nodename, sizeof(buf.nodename));
    strlcpy(buf.release, utsname.release, sizeof(buf.release));
    strlcpy(buf.version, utsname.version, sizeof(buf.version));
    strlcpy(buf.machine, utsname.machine, sizeof(buf.machine));
    if (copy_to_user(user_buf, &buf, sizeof(struct linux_old_utsname)))
        return -EFAULT;
    return 0;
}

long sys_newuname(struct utsname* user_buf) {
    struct utsname buf;
    utsname_get(&buf);
    if (copy_to_user(user_buf, &buf, sizeof(struct utsname)))
        return -EFAULT;
    return 0;
}

long sys_sethostname(const char* user_name, int len) {
    if (len < 0 || UTSNAME_LENGTH <= len)
        return -EINVAL;
    char name[UTSNAME_LENGTH] = {0};
    if (len > 0) {
        ssize_t rc = strncpy_from_user(name, user_name, len);
        if (IS_ERR(rc))
            return rc;
    }
    return utsname_set_hostname(name, len);
}

long sys_setdomainname(const char* user_name, int len) {
    if (len < 0 || UTSNAME_LENGTH <= len)
        return -EINVAL;
    char name[UTSNAME_LENGTH] = {0};
    if (len > 0) {
        ssize_t rc = strncpy_from_user(name, user_name, len);
        if (IS_ERR(rc))
            return rc;
    }
    return utsname_set_domainname(name, len);
}

long sys_getcpu(unsigned int* user_cpu, unsigned int* user_node,
                struct getcpu_cache* user_tcache) {
    (void)user_tcache;
    int rc = 0;
    if (user_cpu) {
        unsigned id = arch_cpu_get_id();
        rc |= copy_to_user(user_cpu, &id, sizeof(unsigned));
    }
    if (user_node) {
        unsigned node = 0;
        rc |= copy_to_user(user_node, &node, sizeof(unsigned));
    }
    return rc ? -EFAULT : 0;
}

long sys_getrandom(void* user_buf, size_t buflen, unsigned int flags) {
    if (flags & ~(GRND_NONBLOCK | GRND_RANDOM))
        return -EINVAL;
    // Our RNG never blocks, so GRND_NONBLOCK has no effect.
    // GRND_RANDOM has no effect in Linux.
    return random_get_user(user_buf, buflen);
}

long sys_dbgprint(const char* user_str) {
    char str[1024];
    ssize_t str_len = strncpy_from_user(str, user_str, sizeof(str));
    if (IS_ERR(str_len))
        return str_len;
    if ((size_t)str_len >= sizeof(str))
        return -E2BIG;
    return kprint(str);
}
