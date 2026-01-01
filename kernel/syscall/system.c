#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/sys/reboot.h>
#include <kernel/api/sys/sysinfo.h>
#include <kernel/cpu.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>
#include <kernel/system.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

// There is no support for users and groups in this kernel.
// It behaves as if the user is always root.

uid_t sys_getuid(void) { return sys_getuid16(); }

linux_old_uid_t sys_getuid16(void) { return 0; }

uid_t sys_geteuid(void) { return sys_geteuid16(); }

linux_old_uid_t sys_geteuid16(void) { return 0; }

gid_t sys_getgid(void) { return sys_getgid16(); }

linux_old_gid_t sys_getgid16(void) { return 0; }

gid_t sys_getegid(void) { return sys_getegid16(); }

linux_old_gid_t sys_getegid16(void) { return 0; }

int sys_getresuid(uid_t* user_ruid, uid_t* user_euid, uid_t* user_suid) {
    uid_t zero = 0;
    if (copy_to_user(user_ruid, &zero, sizeof(uid_t)))
        return -EFAULT;
    if (copy_to_user(user_euid, &zero, sizeof(uid_t)))
        return -EFAULT;
    if (copy_to_user(user_suid, &zero, sizeof(uid_t)))
        return -EFAULT;
    return 0;
}

int sys_getresuid16(linux_old_uid_t* user_ruid, linux_old_uid_t* user_euid,
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

int sys_getresgid(gid_t* user_rgid, gid_t* user_egid, gid_t* user_sgid) {
    gid_t zero = 0;
    if (copy_to_user(user_rgid, &zero, sizeof(gid_t)))
        return -EFAULT;
    if (copy_to_user(user_egid, &zero, sizeof(gid_t)))
        return -EFAULT;
    if (copy_to_user(user_sgid, &zero, sizeof(gid_t)))
        return -EFAULT;
    return 0;
}

int sys_getresgid16(linux_old_gid_t* user_rgid, linux_old_gid_t* user_egid,
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
int sys_getgroups(int size, gid_t* user_list) {
    (void)user_list;
    if (size < 0)
        return -EINVAL;
    return 0;
}

// NOLINTNEXTLINE(readability-non-const-parameter)
int sys_getgroups16(int size, linux_old_gid_t* user_list) {
    (void)user_list;
    if (size < 0)
        return -EINVAL;
    return 0;
}

int sys_reboot(int magic, int magic2, int op, void* user_arg) {
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
        kprint("Restarting system\n");
        reboot();
    case LINUX_REBOOT_CMD_RESTART2: {
        char arg[256] = {0};
        ssize_t rc = strncpy_from_user(arg, user_arg, sizeof(arg));
        if (IS_ERR(rc))
            return rc;
        arg[sizeof(arg) - 1] = 0;
        kprintf("Restarting system with command '%s'\n", arg);
        reboot();
    }
    case LINUX_REBOOT_CMD_HALT:
        kprint("System halted\n");
        halt();
    case LINUX_REBOOT_CMD_POWER_OFF:
        kprint("Power down\n");
        poweroff();
    default:
        return -EINVAL;
    }
}

int sys_sysinfo(struct sysinfo* user_info) {
    struct memory_stats memory_stats;
    memory_get_stats(&memory_stats);

    size_t num_procs = 0;
    {
        SCOPED_LOCK(spinlock, &tasks_lock);
        for (struct task* task = tasks; task; task = task->tasks_next)
            ++num_procs;
    }

    struct sysinfo info = {
        .uptime = divmodi64(uptime, CLK_TCK, NULL),
        .totalram = memory_stats.total_kibibytes,
        .freeram = memory_stats.free_kibibytes,
        .procs = num_procs,
        .mem_unit = 1024,
    };
    if (copy_to_user(user_info, &info, sizeof(struct sysinfo)))
        return -EFAULT;
    return 0;
}

int sys_olduname(struct linux_oldold_utsname* user_buf) {
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

int sys_uname(struct linux_old_utsname* user_buf) {
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

int sys_newuname(struct utsname* user_buf) {
    struct utsname buf;
    utsname_get(&buf);
    if (copy_to_user(user_buf, &buf, sizeof(struct utsname)))
        return -EFAULT;
    return 0;
}

int sys_sethostname(const char* user_name, int len) {
    if (len < 0 || UTSNAME_LENGTH <= len)
        return -EINVAL;
    char name[UTSNAME_LENGTH];
    ssize_t rc = strncpy_from_user(name, user_name, len);
    if (IS_ERR(rc))
        return rc;
    return utsname_set_hostname(name, len);
}

int sys_setdomainname(const char* user_name, int len) {
    if (len < 0 || UTSNAME_LENGTH <= len)
        return -EINVAL;
    char name[UTSNAME_LENGTH];
    ssize_t rc = strncpy_from_user(name, user_name, len);
    if (IS_ERR(rc))
        return rc;
    return utsname_set_domainname(name, len);
}

int sys_getcpu(unsigned int* user_cpu, unsigned int* user_node,
               struct getcpu_cache* user_tcache) {
    (void)user_tcache;
    if (user_cpu) {
        unsigned id = cpu_get_id();
        if (copy_to_user(user_cpu, &id, sizeof(unsigned)))
            return -EFAULT;
    }
    if (user_node) {
        unsigned node = 0;
        if (copy_to_user(user_node, &node, sizeof(unsigned)))
            return -EFAULT;
    }
    return 0;
}

ssize_t sys_getrandom(void* user_buf, size_t buflen, unsigned int flags) {
    (void)flags;
    return random_get_user(user_buf, buflen);
}

int sys_dbgprint(const char* user_str) {
    char str[1024];
    ssize_t str_len = strncpy_from_user(str, user_str, sizeof(str));
    if (IS_ERR(str_len))
        return str_len;
    if ((size_t)str_len >= sizeof(str))
        return -E2BIG;
    return kprint(str);
}
