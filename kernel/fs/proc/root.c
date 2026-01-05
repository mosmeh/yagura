#include "private.h"
#include <common/integer.h>
#include <common/stdio.h>
#include <common/stdlib.h>
#include <kernel/api/dirent.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/containers/vec.h>
#include <kernel/cpu.h>
#include <kernel/device/device.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

static int print_cmdline(struct file* file, struct vec* vec) {
    (void)file;
    return vec_printf(vec, "%s\n", cmdline_get_raw());
}

static int print_flag(struct vec* vec, const struct cpu* cpu, int feature,
                      const char* name) {
    if (!name[0]) {
        // Skip empty names
        return 0;
    }
    if (!cpu_has_feature(cpu, feature))
        return 0;
    return vec_printf(vec, "%s ", name);
}

static int print_cpuinfo(struct file* file, struct vec* vec) {
    (void)file;

    for (size_t i = 0; i < num_cpus; ++i) {
        struct cpu* cpu = cpus[i];
        int ret = vec_printf(vec,
                             "processor       : %zu\n"
                             "vendor_id       : %s\n"
                             "cpu family      : %u\n"
                             "model           : %u\n"
                             "model name      : %s\n",
                             i, cpu->vendor_id, cpu->family, cpu->model,
                             cpu->model_name);
        if (IS_ERR(ret))
            return ret;

        if (cpu->stepping) {
            ret = vec_printf(vec, "stepping        : %u\n", cpu->stepping);
            if (IS_ERR(ret))
                return ret;
        }

        const char* fpu = cpu_has_feature(cpu, X86_FEATURE_FPU) ? "yes" : "no";
        ret = vec_printf(vec,
                         "apicid          : %u\n"
                         "fpu             : %s\n"
                         "fpu_exception   : %s\n"
                         "wp              : yes\n"
                         "flags           : ",
                         cpu->apic_id, fpu, fpu);
        if (IS_ERR(ret))
            return ret;

#define F(variant, name)                                                       \
    ret = print_flag(vec, cpu, X86_FEATURE_##variant, #name);                  \
    if (IS_ERR(ret))                                                           \
        return ret;
        ENUMERATE_X86_FEATURES(F)
#undef F

        ret = vec_printf(
            vec, "\naddress sizes   : %u bits physical, %u bits virtual\n\n",
            cpu->phys_addr_bits, cpu->virt_addr_bits);
        if (IS_ERR(ret))
            return ret;
    }

    return 0;
}

static int print_filesystems(struct file* file, struct vec* vec) {
    (void)file;
    for (struct file_system* fs = file_systems; fs; fs = fs->next) {
        int rc = vec_printf(vec, "%s\n", fs->name);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

static int print_kallsyms(struct file* file, struct vec* vec) {
    (void)file;
    const struct symbol* symbol = NULL;
    while ((symbol = ksyms_next(symbol))) {
        int rc = vec_printf(vec, "%p %c %s\n", (void*)symbol->addr,
                            symbol->type, symbol->name);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

static int print_meminfo(struct file* file, struct vec* vec) {
    (void)file;
    struct memory_stats stats;
    memory_get_stats(&stats);

    return vec_printf(vec,
                      "MemTotal: %8zu kB\n"
                      "MemFree:  %8zu kB\n",
                      stats.total_kibibytes, stats.free_kibibytes);
}

static int print_self(struct file* file, struct vec* vec) {
    (void)file;
    return vec_printf(vec, "%d", current->thread_group->tgid);
}

NODISCARD static int sprintf_ticks(struct vec* vec, unsigned long ticks) {
    unsigned long i = ticks / CLK_TCK;

    // Map [0, CLK_TCK) to [0, 100)
    unsigned long frac = (ticks % CLK_TCK) * 100 / CLK_TCK;

    return vec_printf(vec, "%lu.%02lu", i, frac);
}

static int print_uptime(struct file* file, struct vec* vec) {
    (void)file;

    int rc = sprintf_ticks(vec, uptime);
    if (IS_ERR(rc))
        return rc;
    rc = vec_append(vec, " ", 1);
    if (IS_ERR(rc))
        return rc;

    size_t idle_ticks = 0;
    for (size_t i = 0; i < num_cpus; ++i) {
        struct task* task = cpus[i]->idle_task;
        idle_ticks += task->kernel_ticks;
        ASSERT(task->user_ticks == 0);
    }
    rc = sprintf_ticks(vec, idle_ticks);
    if (IS_ERR(rc))
        return rc;

    return vec_append(vec, "\n", 1);
}

static int print_version(struct file* file, struct vec* vec) {
    (void)file;
    struct utsname utsname;
    utsname_get(&utsname);
    return vec_printf(vec, "%s version %s %s\n", utsname.sysname,
                      utsname.release, utsname.version);
}

static struct proc_entry entries[] = {
    {"cmdline", S_IFREG, print_cmdline},
    {"cpuinfo", S_IFREG, print_cpuinfo},
    {"filesystems", S_IFREG, print_filesystems},
    {"kallsyms", S_IFREG, print_kallsyms},
    {"meminfo", S_IFREG, print_meminfo},
    {"mounts", S_IFREG, proc_print_mounts},
    {"self", S_IFLNK, print_self},
    {"slabinfo", S_IFREG, proc_print_slabinfo},
    {"uptime", S_IFREG, print_uptime},
    {"version", S_IFREG, print_version},
};

struct inode* proc_root_lookup(struct inode* parent, const char* name) {
    if (str_is_uint(name)) {
        pid_t pid = atoi(name);
        return proc_create_inode(parent->mount, pid << PROC_PID_INO_SHIFT,
                                 NULL);
    }
    return proc_lookup(parent, name, entries, ARRAY_SIZE(entries));
}

int proc_root_getdents(struct file* file, getdents_callback_fn callback,
                       void* ctx) {
    SCOPED_LOCK(file, file);
    if (file->offset < ARRAY_SIZE(entries)) {
        int rc =
            proc_getdents(file, callback, ctx, entries, ARRAY_SIZE(entries));
        if (IS_ERR(rc))
            return rc;
    }
    if (file->offset < ARRAY_SIZE(entries))
        return 0;

    SCOPED_LOCK(spinlock, &tasks_lock);

    pid_t offset_pid = (pid_t)(file->offset - ARRAY_SIZE(entries));
    struct task* it = tasks;
    while (it->tid <= offset_pid) {
        it = it->tasks_next;
        if (!it)
            break;
    }

    while (it) {
        char name[16];
        (void)snprintf(name, sizeof(name), "%d", it->tid);

        ino_t ino = it->tid << PROC_PID_INO_SHIFT;

        if (!callback(name, ino, DT_DIR, ctx))
            break;

        file->offset = it->tid + ARRAY_SIZE(entries);
        it = it->tasks_next;
    }

    return 0;
}
