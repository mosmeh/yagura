#include <common/extra.h>
#include <common/libgen.h>
#include <common/string.h>
#include <kernel/api/elf.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/limits.h>
#include <kernel/asm_wrapper.h>
#include <kernel/boot_defs.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/safe_string.h>

typedef struct string_vec {
    size_t count;
    bool is_owned;
    union {
        struct {
            const char** elements;
            char* buffer;
        } owned;
        struct {
            const char* const* elements;
        } borrowed;
    };
} string_vec;

static int string_vec_clone_from_user(string_vec* strings,
                                      const char* const* user_src) {
    strings->is_owned = true;
    strings->count = 0;

    size_t total_size = 0;
    for (const char* const* it = user_src;; ++it) {
        const char* p = NULL;
        if (!copy_from_user(&p, it, sizeof(char*)))
            return -EFAULT;
        if (!p)
            break;
        ssize_t len = strnlen_user(p, ARG_MAX);
        if (IS_ERR(len))
            return -EFAULT;
        if (len >= ARG_MAX)
            return -E2BIG;
        total_size += len + 1;
        ++strings->count;
    }

    if (strings->count == 0) {
        strings->owned.buffer = NULL;
        strings->owned.elements = NULL;
        return 0;
    }

    strings->owned.buffer = kmalloc(total_size);
    if (!strings->owned.buffer)
        return -ENOMEM;

    strings->owned.elements = kmalloc(strings->count * sizeof(char*));
    if (!strings->owned.elements) {
        kfree(strings->owned.buffer);
        strings->owned.buffer = NULL;
        return -ENOMEM;
    }

    char* cursor = strings->owned.buffer;
    for (size_t i = 0; i < strings->count; ++i) {
        size_t size = strlen(user_src[i]) + 1;
        strncpy(cursor, user_src[i], size);
        strings->owned.elements[i] = cursor;
        cursor += size;
    }

    return 0;
}

static void string_vec_borrow_from_kernel(string_vec* strings,
                                          const char* const* src) {
    strings->is_owned = false;
    strings->count = 0;
    for (const char* const* it = src; *it; ++it)
        ++strings->count;
    strings->borrowed.elements = src;
}

static void string_vec_destroy(string_vec* strings) {
    if (!strings->is_owned)
        return;
    if (strings->owned.buffer) {
        kfree(strings->owned.buffer);
        strings->owned.buffer = NULL;
    }
    if (strings->owned.elements) {
        kfree(strings->owned.elements);
        strings->owned.elements = NULL;
    }
}

typedef struct ptr_vec {
    size_t count;
    uintptr_t* elements;
} ptr_vec;

static void ptr_vec_destroy(ptr_vec* ptrs) {
    if (ptrs->elements) {
        kfree(ptrs->elements);
        ptrs->elements = NULL;
    }
}

NODISCARD static int push_value(uintptr_t* sp, uintptr_t stack_base,
                                uintptr_t value) {
    if (*sp - sizeof(uintptr_t) < stack_base)
        return -E2BIG;
    *sp -= sizeof(uintptr_t);
    *(uintptr_t*)*sp = value;
    return 0;
}

NODISCARD static int push_strings(uintptr_t* sp, uintptr_t stack_base,
                                  ptr_vec* ptrs, const string_vec* strings) {
    ptrs->count = strings->count;

    if (strings->count == 0) {
        ptrs->elements = NULL;
        return 0;
    }

    ptrs->elements = kmalloc(strings->count * sizeof(uintptr_t));
    if (!ptrs->elements)
        return -ENOMEM;

    for (ssize_t i = strings->count - 1; i >= 0; --i) {
        const char* str = strings->is_owned ? strings->owned.elements[i]
                                            : strings->borrowed.elements[i];
        size_t size = strlen(str) + 1;
        if (*sp - size < stack_base) {
            kfree(ptrs->elements);
            ptrs->elements = NULL;
            return -E2BIG;
        }
        *sp -= next_power_of_two(size);
        strncpy((char*)*sp, str, size);
        ptrs->elements[ptrs->count - i - 1] = *sp;
    }

    return 0;
}

NODISCARD static int push_ptrs(uintptr_t* sp, uintptr_t stack_base,
                               const ptr_vec* ptrs) {
    for (size_t i = 0; i < ptrs->count; ++i) {
        int rc = push_value(sp, stack_base, ptrs->elements[i]);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

static int execve(const char* pathname, string_vec* argv, string_vec* envp) {
    int ret = 0;
    unsigned char* exe_buf = NULL;
    struct file* file = NULL;

    struct stat stat;
    ret = vfs_stat_at(current->cwd, pathname, &stat, 0);
    if (IS_ERR(ret))
        goto fail_exe;
    if (!S_ISREG(stat.st_mode)) {
        ret = -EACCES;
        goto fail_exe;
    }
    if ((size_t)stat.st_size < sizeof(Elf32_Ehdr)) {
        ret = -ENOEXEC;
        goto fail_exe;
    }

    char copied_pathname[PATH_MAX];
    strncpy(copied_pathname, pathname, PATH_MAX);
    const char* exe_basename = basename(copied_pathname);
    char comm[sizeof(current->comm)];
    strlcpy(comm, exe_basename, sizeof(current->comm));

    file = vfs_open(pathname, O_RDONLY, 0);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        file = NULL;
        goto fail_exe;
    }

    exe_buf = kmalloc(stat.st_size);
    if (!exe_buf) {
        ret = -ENOMEM;
        goto fail_exe;
    }

    ssize_t nread = file_read_to_end(file, exe_buf, stat.st_size);
    file_close(file);
    file = NULL;
    if (IS_ERR(nread)) {
        ret = nread;
        goto fail_exe;
    }

    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)exe_buf;
    if (!IS_ELF(*ehdr) || ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr->e_ident[EI_OSABI] != ELFOSABI_SYSV ||
        ehdr->e_ident[EI_ABIVERSION] != 0 || ehdr->e_machine != EM_386 ||
        ehdr->e_type != ET_EXEC || ehdr->e_version != EV_CURRENT) {
        ret = -ENOEXEC;
        goto fail_exe;
    }

    struct vm* prev_vm = current->vm;

    // Start userland virtual memory range at 1MiB (arbitrary choice)
    struct vm* vm = vm_create((void*)0x100000, (void*)KERNEL_VIRT_ADDR);
    if (IS_ERR(vm)) {
        ret = PTR_ERR(vm);
        goto fail_exe;
    }
    vm_enter(vm);

    ptr_vec envp_ptrs = (ptr_vec){0};
    ptr_vec argv_ptrs = (ptr_vec){0};

    Elf32_Phdr* phdr = (Elf32_Phdr*)(exe_buf + ehdr->e_phoff);
    for (size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if (phdr->p_type != PT_LOAD)
            continue;
        if (phdr->p_filesz > phdr->p_memsz) {
            ret = -ENOEXEC;
            goto fail_vm;
        }

        uintptr_t region_start = round_down(phdr->p_vaddr, PAGE_SIZE);
        uintptr_t region_end =
            round_up(phdr->p_vaddr + phdr->p_memsz, PAGE_SIZE);
        size_t region_size = region_end - region_start;
        void* addr = vm_alloc_at((void*)region_start, region_size,
                                 VM_READ | VM_WRITE | VM_USER);
        if (IS_ERR(addr)) {
            ret = PTR_ERR(addr);
            goto fail_vm;
        }

        memset((void*)region_start, 0, phdr->p_vaddr - region_start);
        memcpy((void*)phdr->p_vaddr, exe_buf + phdr->p_offset, phdr->p_filesz);
        memset((void*)(phdr->p_vaddr + phdr->p_filesz), 0,
               region_end - phdr->p_vaddr - phdr->p_filesz);

        if (!(phdr->p_flags & PF_W)) {
            ret = vm_set_flags((void*)region_start, region_size,
                               VM_READ | VM_USER);
            if (IS_ERR(ret))
                goto fail_vm;
        }
    }

    uint32_t entry_point = ehdr->e_entry;
    kfree(exe_buf);
    exe_buf = NULL;

    void* stack_region =
        vm_alloc(2 * PAGE_SIZE + STACK_SIZE, VM_READ | VM_WRITE | VM_USER);
    if (IS_ERR(stack_region)) {
        ret = PTR_ERR(stack_region);
        goto fail_vm;
    }

    uintptr_t stack_base = (uintptr_t)stack_region + PAGE_SIZE;

    // Make pages before and after the stack inaccessible to detect stack
    // overflow and underflow
    ret = vm_set_flags(stack_region, PAGE_SIZE, VM_USER);
    if (IS_ERR(ret))
        goto fail_vm;
    ret = vm_set_flags((void*)(stack_base + STACK_SIZE), PAGE_SIZE, VM_USER);
    if (IS_ERR(ret))
        goto fail_vm;

    uintptr_t sp = stack_base + STACK_SIZE;
    memset((void*)stack_base, 0, STACK_SIZE);

    uintptr_t env_end = sp;
    ret = push_strings(&sp, stack_base, &envp_ptrs, envp);
    string_vec_destroy(envp);
    if (IS_ERR(ret))
        goto fail_vm;
    uintptr_t env_start = sp;

    uintptr_t arg_end = sp;
    ret = push_strings(&sp, stack_base, &argv_ptrs, argv);
    string_vec_destroy(argv);
    if (IS_ERR(ret))
        goto fail_vm;
    uintptr_t arg_start = sp;

    ret = push_value(&sp, stack_base, 0);
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_ptrs(&sp, stack_base, &envp_ptrs);
    if (IS_ERR(ret))
        goto fail_vm;
    uintptr_t user_envp = sp;
    ptr_vec_destroy(&envp_ptrs);

    ret = push_value(&sp, stack_base, 0);
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_ptrs(&sp, stack_base, &argv_ptrs);
    if (IS_ERR(ret))
        goto fail_vm;
    uintptr_t user_argv = sp;
    ptr_vec_destroy(&argv_ptrs);

    sp = round_down(sp, 16);

    ret = push_value(&sp, stack_base, user_envp);
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_value(&sp, stack_base, user_argv);
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_value(&sp, stack_base, argv->count);
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_value(&sp, stack_base, 0); // fake return address
    if (IS_ERR(ret))
        goto fail_vm;

    if (prev_vm != kernel_vm)
        vm_destroy(prev_vm);

    cli();

    current->eip = entry_point;
    current->esp = current->ebp = current->kernel_stack_top;
    current->ebx = current->esi = current->edi = 0;
    current->fpu_state = initial_fpu_state;

    strlcpy(current->comm, comm, sizeof(current->comm));
    current->arg_start = arg_start;
    current->arg_end = arg_end;
    current->env_start = env_start;
    current->env_end = env_end;

    // enter userland
    __asm__ volatile("movw $0x23, %%ax\n"
                     "movw %%ax, %%ds\n"
                     "movw %%ax, %%es\n"
                     "movw %%ax, %%fs\n"
                     "movw %%ax, %%gs\n"
                     "movl %0, %%esp\n"
                     "pushl $0x23\n"
                     "pushl %0\n"
                     "pushf\n"
                     "popl %%eax\n"
                     "orl $0x200, %%eax\n" // set IF
                     "pushl %%eax\n"
                     "pushl $0x1b\n"
                     "push %1\n"
                     "iret" ::"r"(sp),
                     "r"(entry_point)
                     : "eax");
    UNREACHABLE();

fail_vm:
    ptr_vec_destroy(&envp_ptrs);
    ptr_vec_destroy(&argv_ptrs);
    vm_destroy(vm);
    vm_enter(prev_vm);

fail_exe:
    kfree(exe_buf);
    if (file)
        file_close(file);
    string_vec_destroy(envp);
    string_vec_destroy(argv);

    return ret;
}

int process_user_execve(const char* pathname, const char* const* user_argv,
                        const char* const* user_envp) {
    if (!pathname || !user_argv || !user_envp)
        return -EFAULT;

    string_vec argv = (string_vec){0};
    int rc = string_vec_clone_from_user(&argv, user_argv);
    if (IS_ERR(rc))
        return rc;

    string_vec envp = (string_vec){0};
    rc = string_vec_clone_from_user(&envp, user_envp);
    if (IS_ERR(rc)) {
        string_vec_destroy(&argv);
        return rc;
    }

    return execve(pathname, &argv, &envp);
}

int process_kernel_execve(const char* pathname, const char* const* argv,
                          const char* const* envp) {
    string_vec argv_vec = (string_vec){0};
    string_vec_borrow_from_kernel(&argv_vec, argv);

    string_vec envp_vec = (string_vec){0};
    string_vec_borrow_from_kernel(&envp_vec, envp);

    return execve(pathname, &argv_vec, &envp_vec);
}
