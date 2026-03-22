#include <kernel/api/fcntl.h>
#include <kernel/api/sched.h>
#include <kernel/arch/system.h>
#include <kernel/console/console.h>
#include <kernel/cpu.h>
#include <kernel/device/device.h>
#include <kernel/drivers/drivers.h>
#include <kernel/drivers/serial.h>
#include <kernel/exec/exec.h>
#include <kernel/fs/file.h>
#include <kernel/fs/fs.h>
#include <kernel/fs/vfs.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/sched.h>
#include <kernel/socket.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

static void open_console(void) {
    struct file* file FREE(file) =
        ASSERT(vfs_open(BASE_CWD, "/dev/console", O_RDWR, 0));
    if (IS_ERR(file)) {
        kprint("userland_init: warning: unable to open an initial console\n");
        return;
    }
    int rc;
    for (int i = 0; i < 3; ++i)
        rc = fd_table_alloc_fd(current->fd_table, 0, file, 0);
    (void)rc;
}

NODISCARD static int run_init(const char* path) {
    const char* argv[] = {path, NULL};
    static const char* const envp[] = {"HOME=/", "TERM=linux", NULL};
    kprintf("userland_init: run %s as init process\n", path);
    return execve_kernel(path, argv, envp);
}

static _Noreturn void userland_init(void) {
    ASSERT(current->tid == 1);
    ASSERT(current->thread_group->tgid == 1);
    ASSERT(current->thread_group->pgid == 0);
    ASSERT(current->thread_group->ppid == 0);

    ASSERT_OK(task_unshare(CLONE_FS | CLONE_FILES));

    open_console();

    const char* init_path = cmdline_lookup("init");
    if (init_path) {
        int rc = run_init(init_path);
        if (IS_ERR(rc))
            PANIC("Requested init %s failed (error %d)", init_path, rc);
    }

    static const char* const default_init_paths[] = {
        "/init", "/sbin/init", "/etc/init", "/bin/init", "/bin/sh",
    };
    for (size_t i = 0; i < ARRAY_SIZE(default_init_paths); ++i) {
        const char* path = default_init_paths[i];
        int rc = run_init(path);
        if (rc != -ENOENT) {
            kprintf("userland_init: starting init: "
                    "%s exists but couldn't execute it (error %d)\n",
                    path, rc);
        }
    }

    PANIC("No working init found. Try passing init= option to kernel.");
}

static _Noreturn void kworker(void) {
    for (;;)
        workqueue_dispatch(global_workqueue);
}

static _Noreturn void kernel_init(void) {
    ksyms_init();
    fs_init();
    device_init();
    drivers_init();
    console_init();
    random_init();
    socket_init();
    time_init();
    arch_late_init();

    ASSERT_OK(task_spawn("kworker", kworker));

    userland_init(); // Become the userland init process
}

_Noreturn void kernel_main(void) {
    kprint("version: " YAGURA_VERSION "\n");

    task_early_init();
    memory_init();
    arch_enable_interrupts(); // Allow sleeping for memory allocation
    task_late_init();
    ASSERT_OK(task_spawn("init", kernel_init));
    sched_start();
}
