#include "private.h"
#include <common/integer.h>
#include <common/libgen.h>
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/exec/exec.h>
#include <kernel/fs/file.h>
#include <kernel/fs/path.h>
#include <kernel/interrupts.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/task.h>

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
static int copy_from_kernel_to_remote_vm(struct vm* vm, void* user_dest,
                                         const void* src, size_t size) {
    ASSERT(vm_is_locked_by_current(vm));
    size_t offset = 0;
    while (offset < size) {
        uintptr_t curr_addr = (uintptr_t)user_dest + offset;
        struct page* page = vm_get_page(vm, (void*)curr_addr);
        if (IS_ERR(ASSERT(page)))
            return PTR_ERR(page);
        size_t page_offset = curr_addr % PAGE_SIZE;
        size_t to_copy = MIN(PAGE_SIZE - page_offset, size - offset);
        page_copy_from_buffer(page, (const unsigned char*)src + offset,
                              page_offset, to_copy);
        offset += to_copy;
    }
    return 0;
}

NODISCARD
static int copy_from_user_to_remote_vm(struct vm* vm, void* user_dest,
                                       const void* user_src, size_t size) {
    ASSERT(vm_is_locked_by_current(vm));
    size_t offset = 0;
    while (offset < size) {
        uintptr_t curr_addr = (uintptr_t)user_dest + offset;
        struct page* page = vm_get_page(vm, (void*)curr_addr);
        if (IS_ERR(ASSERT(page)))
            return PTR_ERR(page);
        size_t page_offset = curr_addr % PAGE_SIZE;
        size_t to_copy = MIN(PAGE_SIZE - page_offset, size - offset);
        unsigned char buffer[PAGE_SIZE];
        if (copy_from_user(buffer, (const unsigned char*)user_src + offset,
                           to_copy))
            return -EFAULT;
        page_copy_from_buffer(page, buffer, page_offset, to_copy);
        offset += to_copy;
    }
    return 0;
}

int exec_image_load(struct exec_image* image, const char* pathname) {
    struct path* path FREE(path) = vfs_resolve_path(pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);

    struct kstat stat;
    int rc = inode_stat(path->inode, &stat);
    if (IS_ERR(rc))
        return rc;
    if (!S_ISREG(stat.st_mode))
        return -EACCES;

    struct file* file FREE(file) = inode_open(path->inode, O_RDONLY);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    struct vm_obj* vm_obj FREE(vm_obj) = file_mmap(file);
    if (IS_ERR(ASSERT(vm_obj)))
        return PTR_ERR(vm_obj);

    void* data = vm_obj_map(vm_obj, 0, DIV_CEIL(stat.st_size, PAGE_SIZE),
                            VM_READ | VM_WRITE);
    if (IS_ERR(ASSERT(data)))
        return PTR_ERR(data);

    exec_image_unload(image);

    image->obj = TAKE_PTR(vm_obj);
    image->data = data;
    return rc;
}

void exec_image_unload(struct exec_image* image) {
    if (image->data) {
        vm_obj_unmap(image->data);
        image->data = NULL;
    }
    if (image->obj) {
        vm_obj_unref(image->obj);
        image->obj = NULL;
    }
}

NODISCARD static int loader_init_vm(struct loader* loader) {
    struct vm* vm FREE(vm) = vm_create(0, (void*)USER_VIRT_END);
    if (IS_ERR(ASSERT(vm)))
        return PTR_ERR(vm);

    SCOPED_LOCK(vm, vm);

    STATIC_ASSERT(STACK_SIZE % PAGE_SIZE == 0);

    size_t npages = 2 + (STACK_SIZE >> PAGE_SHIFT);
    unsigned char* guard_start = (void*)(USER_VIRT_END - npages * PAGE_SIZE);
    struct vm_region* region = vm_alloc_at(vm, guard_start, npages);
    if (IS_ERR(ASSERT(region)))
        return PTR_ERR(region);

    // Split the region into three:
    // guard (PAGE_SIZE), stack (STACK_SIZE), and guard (PAGE_SIZE)
    int rc = vm_region_set_flags(region, 1, STACK_SIZE >> PAGE_SHIFT,
                                 VM_READ | VM_WRITE | VM_EXEC | VM_USER, ~0);
    if (IS_ERR(rc))
        return rc;

    unsigned char* stack_base = guard_start + PAGE_SIZE;

    // Get the middle region, which is the stack
    struct vm_region* stack_region = vm_find(vm, (void*)stack_base);
    ASSERT(stack_region);

    struct vm_obj* stack_obj FREE(vm_obj) = anon_create();
    if (IS_ERR(ASSERT(stack_obj)))
        return PTR_ERR(stack_obj);
    vm_region_set_obj(stack_region, stack_obj, 0);

    loader->vm = TAKE_PTR(vm);
    loader->stack_base = stack_base;
    loader->stack_ptr = stack_base + STACK_SIZE;
    return rc;
}

static void loader_deinit_vm(struct loader* loader) {
    if (loader->vm) {
        vm_unref(loader->vm);
        loader->vm = NULL;
    }
}

static void loader_deinit(struct loader* loader) {
    loader_deinit_vm(loader);
    exec_image_unload(&loader->image);
}

NODISCARD static int loader_init(struct loader* loader, const char* pathname) {
    *loader = (struct loader){0};

    size_t path_len = strnlen(pathname, PATH_MAX);
    if (path_len >= PATH_MAX)
        return -ENAMETOOLONG;
    strlcpy(loader->pathname, pathname, path_len + 1);

    int rc = exec_image_load(&loader->image, pathname);
    if (IS_ERR(rc))
        goto fail;

    rc = loader_init_vm(loader);
    if (IS_ERR(rc))
        goto fail;

    return rc;

fail:
    loader_deinit(loader);
    return rc;
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
    return copy_from_kernel_to_remote_vm(vm, new_sp, str, size);
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
    return copy_from_user_to_remote_vm(vm, new_sp, user_str, size);
}

int loader_pop_string(struct loader* loader) {
    ssize_t len = strnlen_user((const char*)loader->stack_ptr, ARG_MAX);
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

    if (refcount_get(&task->files->refcount) > 1) {
        struct files* new_files = files_clone(task->files);
        if (IS_ERR(ASSERT(new_files)))
            return PTR_ERR(new_files);
        files_unref(task->files);
        task->files = new_files;
    }

    if (refcount_get(&task->sighand->refcount) > 1) {
        struct sighand* new_sighand = sighand_clone(task->sighand);
        if (IS_ERR(ASSERT(new_sighand)))
            return PTR_ERR(new_sighand);
        sighand_unref(task->sighand);
        task->sighand = new_sighand;
    }

    int rc = files_close_on_exec(task->files);
    if (IS_ERR(rc))
        return rc;

    const char* comm = basename(loader->pathname);
    strlcpy(task->comm, comm, sizeof(task->comm));

    task->arg_start = (uintptr_t)loader->arg_start;
    task->arg_end = (uintptr_t)loader->arg_end;
    task->env_start = (uintptr_t)loader->env_start;
    task->env_end = (uintptr_t)loader->env_end;

    return 0;
}

_Noreturn static void loader_commit(struct loader* loader) {
    ASSERT(loader->entry_point);
    ASSERT(loader->arg_start);
    ASSERT(loader->arg_end);
    ASSERT(loader->env_start);
    ASSERT(loader->env_end);

    exec_image_unload(&loader->image);

    // Point of no return

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
    struct vm* prev_vm = vm_enter(loader->vm);
    mutex_lock(&loader->vm->lock);

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
            mutex_unlock(&loader->vm->lock);
            vm_unref(prev_vm);
            loader_commit(loader);
        }
        if (IS_ERR(rc)) {
            // An error occurred or no loader could handle the executable
            break;
        }
    }

    ASSERT(IS_ERR(rc));
    mutex_unlock(&loader->vm->lock);
    vm_enter(prev_vm);
    return rc;
}

int execve_kernel(const char* pathname, const char* const* argv,
                  const char* const* envp) {
    ASSERT_PTR(pathname);
    ASSERT_PTR(argv);
    ASSERT_PTR(envp);

    struct loader loader;
    int rc = loader_init(&loader, pathname);
    if (IS_ERR(rc))
        return rc;

    rc = loader_push_string_from_kernel(&loader, pathname);
    if (IS_ERR(rc))
        goto fail;
    loader.execfn = (void*)loader.stack_ptr;

    loader.envc = count_strings_kernel(envp);
    loader.env_end = loader.stack_ptr;
    rc = loader_push_strings_from_kernel(&loader, envp, loader.envc);
    if (IS_ERR(rc))
        goto fail;
    loader.env_start = loader.stack_ptr;

    loader.argc = count_strings_kernel(argv);
    if (loader.argc == 0) {
        rc = -EINVAL;
        goto fail;
    }
    loader.arg_end = loader.stack_ptr;
    rc = loader_push_strings_from_kernel(&loader, argv, loader.argc);
    if (IS_ERR(rc))
        goto fail;
    loader.arg_start = loader.stack_ptr;

    rc = loader_load(&loader);

fail:
    loader_deinit(&loader);
    return rc;
}

int execve_user(const char* pathname, const char* const* user_argv,
                const char* const* user_envp) {
    ASSERT_PTR(pathname);
    if (user_argv && !is_user_address(user_argv))
        return -EFAULT;
    if (user_envp && !is_user_address(user_envp))
        return -EFAULT;

    struct loader loader;
    int rc = loader_init(&loader, pathname);
    if (IS_ERR(rc))
        return rc;

    rc = loader_push_string_from_kernel(&loader, pathname);
    if (IS_ERR(rc))
        goto fail;
    loader.execfn = (void*)loader.stack_ptr;

    loader.env_end = loader.stack_ptr;
    if (user_envp) {
        loader.envc = count_strings_user(user_envp);
        if (IS_ERR(loader.envc)) {
            rc = loader.envc;
            goto fail;
        }
        rc = loader_push_strings_from_user(&loader, user_envp, loader.envc);
        if (IS_ERR(rc))
            goto fail;
    } else {
        loader.envc = 0;
    }
    loader.env_start = loader.stack_ptr;

    loader.arg_end = loader.stack_ptr;
    if (user_argv) {
        loader.argc = count_strings_user(user_argv);
        if (IS_ERR(loader.argc)) {
            rc = loader.argc;
            goto fail;
        }
    } else {
        loader.argc = 0;
    }
    if (loader.argc > 0) {
        rc = loader_push_strings_from_user(&loader, user_argv, loader.argc);
    } else {
        // Linux provides an empty string as argv[0] if argv is empty
        static const char* const empty_argv[] = {"", NULL};
        rc = loader_push_strings_from_kernel(&loader, empty_argv, 1);
    }
    if (IS_ERR(rc))
        goto fail;
    loader.arg_start = loader.stack_ptr;

    rc = loader_load(&loader);

fail:
    loader_deinit(&loader);
    return rc;
}
