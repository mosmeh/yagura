#include "private.h"
#include <common/integer.h>
#include <common/libgen.h>
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sched.h>
#include <kernel/exec/exec.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/path.h>
#include <kernel/fs/vfs.h>
#include <kernel/interrupts.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/task.h>

#define USER_STACK_SIZE 0x20000

static size_t count_strings_kernel(const char* const* strings) {
    size_t count = 0;
    for (const char* const* it = strings; *it; ++it)
        ++count;
    return count;
}

NODISCARD static ssize_t count_strings_user(const char* const* user_strings) {
    size_t count = 0;
    for (;;) {
        const char* user_str = NULL;
        if (copy_from_user(&user_str, &user_strings[count],
                           sizeof(const char*)))
            return -EFAULT;
        if (!user_str)
            break;
        ++count;
    }
    return count;
}

NODISCARD
static int copy_from_user_to_vm(struct vm* vm, void* dest, const void* user_src,
                                size_t size) {
    ASSERT(vm_is_locked_by_current(vm));
    size_t offset = 0;
    size_t page_offset = (uintptr_t)dest % PAGE_SIZE;
    while (size > 0) {
        struct page* page FREE(page) =
            vm_get_page(vm, (unsigned char*)dest + offset, VM_WRITE);
        if (IS_ERR(page))
            return PTR_ERR(page);
        if (!page)
            return -EFAULT;
        size_t to_copy = MIN(PAGE_SIZE - page_offset, size);
        unsigned char buffer[PAGE_SIZE];
        if (copy_from_user(buffer, (const unsigned char*)user_src + offset,
                           to_copy))
            return -EFAULT;
        copy_to_page(page, buffer, page_offset, to_copy);
        size -= to_copy;
        offset += to_copy;
        page_offset = 0;
    }
    return 0;
}

struct vm_obj* exec_open(const char* pathname) {
    struct path* path FREE(path) =
        ASSERT(vfs_resolve_path(BASE_CWD, pathname, 0));
    if (IS_ERR(path))
        return ERR_CAST(path);
    if (!S_ISREG(path->inode->mode))
        return ERR_PTR(-EACCES);
    struct file* file FREE(file) = ASSERT(inode_open(path->inode, O_RDONLY));
    if (IS_ERR(file))
        return ERR_CAST(file);
    return file_mmap(file);
}

int loader_open(struct loader* loader, const char* pathname) {
    struct vm_obj* vm_obj = ASSERT(exec_open(pathname));
    if (IS_ERR(vm_obj))
        return PTR_ERR(vm_obj);
    vm_obj_unref(loader->vm_obj);
    loader->vm_obj = vm_obj;
    return 0;
}

NODISCARD static int loader_init_vm(struct loader* loader) {
    struct vm* vm FREE(vm) = ASSERT(vm_create(0, (void*)USER_VIRT_END));
    if (IS_ERR(vm))
        return PTR_ERR(vm);

    SCOPED_LOCK(vm, vm);

    STATIC_ASSERT(USER_STACK_SIZE % PAGE_SIZE == 0);

    size_t npages = 2 + (USER_STACK_SIZE >> PAGE_SHIFT);
    unsigned char* guard_start = (void*)(USER_VIRT_END - npages * PAGE_SIZE);
    struct vm_region* region = ASSERT(vm_alloc_at(vm, guard_start, npages));
    if (IS_ERR(region))
        return PTR_ERR(region);

    // Split the region into three:
    // guard (PAGE_SIZE), stack (USER_STACK_SIZE), and guard (PAGE_SIZE)
    int rc = vm_region_set_flags(region, 1, USER_STACK_SIZE >> PAGE_SHIFT,
                                 VM_READ | VM_WRITE | VM_EXEC | VM_USER, ~0);
    if (IS_ERR(rc))
        return rc;

    unsigned char* stack_base = guard_start + PAGE_SIZE;

    // Get the middle region, which is the stack
    struct vm_region* stack_region = ASSERT_PTR(vm_find(vm, (void*)stack_base));

    struct vm_obj* stack_obj FREE(vm_obj) = ASSERT(anon_create());
    if (IS_ERR(stack_obj))
        return PTR_ERR(stack_obj);
    vm_region_set_obj(stack_region, stack_obj, 0);

    loader->vm = TAKE_PTR(vm);
    loader->stack_base = stack_base;
    loader->stack_ptr = stack_base + USER_STACK_SIZE;
    return rc;
}

NODISCARD static int loader_init(struct loader* loader, const char* pathname) {
    *loader = (struct loader){0};

    size_t path_len = strnlen(pathname, PATH_MAX);
    if (path_len >= PATH_MAX)
        return -ENAMETOOLONG;
    strlcpy(loader->pathname, pathname, path_len + 1);

    int rc = loader_open(loader, pathname);
    if (IS_ERR(rc))
        return rc;

    return loader_init_vm(loader);
}

static void loader_deinit(struct loader* loader) {
    vm_obj_unref(loader->vm_obj);
    loader->vm_obj = NULL;
    vm_unref(loader->vm);
    loader->vm = NULL;
}

int loader_push_string_from_kernel(struct loader* loader, const char* str) {
    size_t size = strnlen(str, ARG_MAX);
    if (size >= ARG_MAX)
        return -E2BIG;
    ++size; // Include null terminator

    unsigned char* new_sp = loader->stack_ptr - size;
    if (new_sp < loader->stack_base)
        return -E2BIG;
    loader->stack_ptr = new_sp;

    struct vm* vm = loader->vm;
    SCOPED_LOCK(vm, vm);
    return copy_to_vm(vm, new_sp, str, size);
}

int loader_push_string_from_user(struct loader* loader, const char* user_str) {
    ssize_t size = strnlen_user(user_str, ARG_MAX);
    if (IS_ERR(size))
        return size;
    if (size >= ARG_MAX)
        return -E2BIG;
    ++size; // Include null terminator

    unsigned char* new_sp = loader->stack_ptr - size;
    if (new_sp < loader->stack_base)
        return -E2BIG;
    loader->stack_ptr = new_sp;

    struct vm* vm = loader->vm;
    SCOPED_LOCK(vm, vm);
    return copy_from_user_to_vm(vm, new_sp, user_str, size);
}

int loader_pop_string(struct loader* loader) {
    ssize_t len =
        vm_strnlen(loader->vm, (const char*)loader->stack_ptr, ARG_MAX);
    if (IS_ERR(len))
        return len;
    if (len >= ARG_MAX)
        return -E2BIG;
    ++len; // Include null terminator
    loader->stack_ptr += len;
    return 0;
}

NODISCARD static int loader_push_strings_from_kernel(struct loader* loader,
                                                     const char* const* string,
                                                     size_t count) {
    for (ssize_t i = count - 1; i >= 0; --i) {
        int rc = loader_push_string_from_kernel(loader, string[i]);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

NODISCARD static int
loader_push_strings_from_user(struct loader* loader,
                              const char* const* user_strings, size_t count) {
    for (ssize_t i = count - 1; i >= 0; --i) {
        const char* user_str = NULL;
        if (copy_from_user(&user_str, &user_strings[i], sizeof(const char*)))
            return -EFAULT;
        int rc = loader_push_string_from_user(loader, user_str);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

NODISCARD static int finalize_exec(struct loader* loader) {
    struct task* task = current;
    SCOPED_LOCK(task, task);

    int rc = task_unshare(CLONE_FILES);
    if (IS_ERR(rc))
        return rc;

    if (refcount_get(&task->sighand->refcount) > 1) {
        struct sighand* new_sighand = ASSERT(sighand_clone(task->sighand));
        if (IS_ERR(new_sighand))
            return PTR_ERR(new_sighand);
        struct sighand* old_sighand = NULL;
        {
            SCOPED_LOCK(spinlock, &tasks_lock);
            old_sighand = task->sighand;
            task->sighand = new_sighand;
        }
        sighand_unref(old_sighand);
    }

    rc = fd_table_close_on_exec(task->fd_table);
    if (IS_ERR(rc))
        return rc;

    const char* comm = basename(loader->pathname);
    strlcpy(task->comm, comm, sizeof(task->comm));

    {
        struct sighand* sighand = task->sighand;
        SCOPED_LOCK(sighand, sighand);
        for (size_t i = 0; i < ARRAY_SIZE(sighand->actions); ++i) {
            struct sigaction* action = &sighand->actions[i];
            sighandler_t handler =
                action->sa_handler == SIG_IGN ? SIG_IGN : SIG_DFL;
            *action = (struct sigaction){.sa_handler = handler};
        }
    }

    task->arg_start = (uintptr_t)loader->arg_start;
    task->arg_end = (uintptr_t)loader->arg_end;
    task->env_start = (uintptr_t)loader->env_start;
    task->env_end = (uintptr_t)loader->env_end;

    return 0;
}

// Point of no return.
_Noreturn static void loader_commit(struct loader* loader) {
    ASSERT_PTR(loader->entry_point);
    ASSERT_PTR(loader->arg_start);
    ASSERT_PTR(loader->arg_end);
    ASSERT_PTR(loader->env_start);
    ASSERT_PTR(loader->env_end);

    vm_enter(loader->vm);
    loader_deinit(loader);

    int rc = finalize_exec(loader);
    if (IS_ERR(rc))
        task_crash(SIGSEGV);

    arch_disable_interrupts();
    arch_enter_user_mode(current, loader->entry_point, loader->stack_ptr);
}

NODISCARD static int loader_load(struct loader* loader) {
    static int (*const loaders[])(struct loader*) = {
        elf_load,
        shebang_load,
    };

    int rc = 0;
    vm_lock(loader->vm);

    for (size_t depth = 0;; ++depth) {
        // Linux imposes a limit of 4 interpreter recursions
        if (depth > 4) {
            rc = -ELOOP;
            break;
        }
        for (size_t i = 0; i < ARRAY_SIZE(loaders); ++i) {
            rc = loaders[i](loader);
            if (rc == -ENOEXEC)
                continue;
            if (IS_ERR(rc) || !loader->commit)
                break;
            vm_unlock(loader->vm);
            loader_commit(loader);
        }
        if (IS_ERR(rc)) {
            // An error occurred or no loader could handle the executable
            break;
        }
    }

    ASSERT(IS_ERR(rc));
    vm_unlock(loader->vm);
    return rc;
}

int execve_kernel(const char* pathname, const char* const* argv,
                  const char* const* envp) {
    ASSERT_PTR(pathname);
    ASSERT_PTR(argv);
    ASSERT_PTR(envp);

    struct loader loader CLEANUP(loader_deinit) = {0};
    int rc = loader_init(&loader, pathname);
    if (IS_ERR(rc))
        return rc;

    rc = loader_push_string_from_kernel(&loader, pathname);
    if (IS_ERR(rc))
        return rc;
    loader.execfn = (void*)loader.stack_ptr;

    loader.envc = count_strings_kernel(envp);
    loader.env_end = loader.stack_ptr;
    rc = loader_push_strings_from_kernel(&loader, envp, loader.envc);
    if (IS_ERR(rc))
        return rc;
    loader.env_start = loader.stack_ptr;

    loader.argc = count_strings_kernel(argv);
    if (loader.argc == 0)
        return -EINVAL;
    loader.arg_end = loader.stack_ptr;
    rc = loader_push_strings_from_kernel(&loader, argv, loader.argc);
    if (IS_ERR(rc))
        return rc;
    loader.arg_start = loader.stack_ptr;

    return loader_load(&loader);
}

int execve_user(const char* pathname, const char* const* user_argv,
                const char* const* user_envp) {
    ASSERT_PTR(pathname);
    if (user_argv && !is_user_address(user_argv))
        return -EFAULT;
    if (user_envp && !is_user_address(user_envp))
        return -EFAULT;

    struct loader loader CLEANUP(loader_deinit) = {0};
    int rc = loader_init(&loader, pathname);
    if (IS_ERR(rc))
        return rc;

    rc = loader_push_string_from_kernel(&loader, pathname);
    if (IS_ERR(rc))
        return rc;
    loader.execfn = (void*)loader.stack_ptr;

    loader.env_end = loader.stack_ptr;
    if (user_envp) {
        loader.envc = count_strings_user(user_envp);
        if (IS_ERR(loader.envc))
            return loader.envc;
        rc = loader_push_strings_from_user(&loader, user_envp, loader.envc);
        if (IS_ERR(rc))
            return rc;
    } else {
        loader.envc = 0;
    }
    loader.env_start = loader.stack_ptr;

    loader.arg_end = loader.stack_ptr;
    if (user_argv) {
        loader.argc = count_strings_user(user_argv);
        if (IS_ERR(loader.argc))
            return loader.argc;
    } else {
        loader.argc = 0;
    }
    if (loader.argc > 0) {
        rc = loader_push_strings_from_user(&loader, user_argv, loader.argc);
    } else {
        // Linux provides an empty string as argv[0] if argv is empty
        loader.argc = 1;
        static const char* const empty_argv[] = {"", NULL};
        rc = loader_push_strings_from_kernel(&loader, empty_argv, 1);
    }
    if (IS_ERR(rc))
        return rc;
    loader.arg_start = loader.stack_ptr;

    return loader_load(&loader);
}
