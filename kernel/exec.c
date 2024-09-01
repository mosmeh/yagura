#include "api/asm/processor-flags.h"
#include "api/elf.h"
#include "api/fcntl.h"
#include "api/sys/limits.h"
#include "asm_wrapper.h"
#include "cpu.h"
#include "gdt.h"
#include "panic.h"
#include "safe_string.h"
#include "task.h"
#include "time.h"
#include <common/extra.h>
#include <common/libgen.h>
#include <common/string.h>

struct string_vec {
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
};

static int string_vec_clone_from_user(struct string_vec* strings,
                                      const char* const* user_src) {
    strings->is_owned = true;
    strings->count = 0;

    size_t total_size = 0;
    for (const char* const* it = user_src;; ++it) {
        const char* p = NULL;
        if (copy_from_user(&p, it, sizeof(char*)))
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

static void string_vec_borrow_from_kernel(struct string_vec* strings,
                                          const char* const* src) {
    strings->is_owned = false;
    strings->count = 0;
    for (const char* const* it = src; *it; ++it)
        ++strings->count;
    strings->borrowed.elements = src;
}

static void string_vec_destroy(struct string_vec* strings) {
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

struct ptr_vec {
    size_t count;
    uintptr_t* elements;
};

static void ptr_vec_destroy(struct ptr_vec* ptrs) {
    if (ptrs->elements) {
        kfree(ptrs->elements);
        ptrs->elements = NULL;
    }
}

NODISCARD static int push_value(uintptr_t* sp, uintptr_t stack_base,
                                uintptr_t value) {
    uintptr_t new_sp = *sp - sizeof(uintptr_t);
    if (new_sp < stack_base)
        return -E2BIG;
    *sp = new_sp;
    *(uintptr_t*)new_sp = value;
    return 0;
}

NODISCARD static int push_strings(uintptr_t* sp, uintptr_t stack_base,
                                  struct ptr_vec* ptrs,
                                  const struct string_vec* strings) {
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
        uintptr_t new_sp = *sp - next_power_of_two(size);
        if (new_sp < stack_base) {
            kfree(ptrs->elements);
            ptrs->elements = NULL;
            return -E2BIG;
        }
        *sp = new_sp;
        strncpy((char*)new_sp, str, size);
        ptrs->elements[ptrs->count - i - 1] = new_sp;
    }

    return 0;
}

NODISCARD static int push_ptrs(uintptr_t* sp, uintptr_t stack_base,
                               const struct ptr_vec* ptrs) {
    for (size_t i = 0; i < ptrs->count; ++i) {
        int rc = push_value(sp, stack_base, ptrs->elements[i]);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

static int execve(const char* pathname, struct string_vec* argv,
                  struct string_vec* envp) {
    int ret = 0;
    unsigned char* exe_buf = NULL;
    struct file* file = NULL;

    struct stat stat;
    mutex_lock(&current->fs->lock);
    ret = vfs_stat_at(current->fs->cwd, pathname, &stat, 0);
    mutex_unlock(&current->fs->lock);
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

    struct ptr_vec envp_ptrs = (struct ptr_vec){0};
    struct ptr_vec argv_ptrs = (struct ptr_vec){0};

    uintptr_t phdr_virt_addr = 0;
    Elf32_Phdr* phdr = (Elf32_Phdr*)(exe_buf + ehdr->e_phoff);
    for (size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if (phdr->p_type != PT_LOAD)
            continue;
        if (phdr->p_filesz > phdr->p_memsz) {
            ret = -ENOEXEC;
            goto fail_vm;
        }

        if (phdr->p_offset <= ehdr->e_phoff &&
            ehdr->e_phoff < phdr->p_offset + phdr->p_filesz)
            phdr_virt_addr = ehdr->e_phoff - phdr->p_offset + phdr->p_vaddr;

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

    ret = push_value(&sp, stack_base, 0); // Sentinel
    if (IS_ERR(ret))
        goto fail_vm;

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

    uint32_t random[4];
    nread = random_get(random, sizeof(random));
    if (IS_ERR(nread)) {
        ret = nread;
        goto fail_vm;
    }
    for (size_t i = 0; i < ARRAY_SIZE(random); ++i) {
        ret = push_value(&sp, stack_base, random[i]);
        if (IS_ERR(ret))
            goto fail_vm;
    }
    uintptr_t random_ptr = sp;

    uintptr_t entry_point = ehdr->e_entry;
    Elf32_auxv_t auxv[] = {
        {AT_PHDR, {phdr_virt_addr}},
        {AT_PHENT, {ehdr->e_phentsize}},
        {AT_PHNUM, {ehdr->e_phnum}},
        {AT_PAGESZ, {PAGE_SIZE}},
        {AT_ENTRY, {entry_point}},
        {AT_UID, {0}},
        {AT_EUID, {0}},
        {AT_GID, {0}},
        {AT_EGID, {0}},
        {AT_HWCAP, {cpu_get_bsp()->features[0]}},
        {AT_CLKTCK, {CLK_TCK}},
        {AT_SECURE, {0}},
        {AT_RANDOM, {random_ptr}},
        {AT_EXECFN, {arg_start}},
        {AT_NULL, {0}},
    };

    kfree(exe_buf);
    exe_buf = NULL;

    sp = round_down(sp, 16);

    for (ssize_t i = ARRAY_SIZE(auxv) - 1; i >= 0; --i) {
        Elf32_auxv_t* aux = auxv + i;
        ret = push_value(&sp, stack_base, aux->a_un.a_val);
        if (IS_ERR(ret))
            goto fail_vm;
        ret = push_value(&sp, stack_base, aux->a_type);
        if (IS_ERR(ret))
            goto fail_vm;
    }

    ret = push_value(&sp, stack_base, 0); // Sentinel
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_ptrs(&sp, stack_base, &envp_ptrs);
    if (IS_ERR(ret))
        goto fail_vm;
    uintptr_t user_envp = sp;
    ptr_vec_destroy(&envp_ptrs);

    ret = push_value(&sp, stack_base, 0); // Sentinel
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_ptrs(&sp, stack_base, &argv_ptrs);
    if (IS_ERR(ret))
        goto fail_vm;
    uintptr_t user_argv = sp;
    ptr_vec_destroy(&argv_ptrs);

    ret = push_value(&sp, stack_base, argv->count);
    if (IS_ERR(ret))
        goto fail_vm;

    // Arguments of the entry point
    ret = push_value(&sp, stack_base, user_envp); // envp
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_value(&sp, stack_base, user_argv); // argv
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_value(&sp, stack_base, argv->count); // argc
    if (IS_ERR(ret))
        goto fail_vm;
    ret = push_value(&sp, stack_base, 0); // fake return address
    if (IS_ERR(ret))
        goto fail_vm;

    if (prev_vm != kernel_vm)
        vm_unref(prev_vm);

    cli();
    struct task* task = current;

    task->eip = entry_point;
    task->esp = task->ebp = sp;
    task->ebx = task->esi = task->edi = 0;
    task->fpu_state = initial_fpu_state;

    strlcpy(task->comm, comm, sizeof(task->comm));
    task->arg_start = arg_start;
    task->arg_end = arg_end;
    task->env_start = env_start;
    task->env_end = env_end;

    // enter userland
    __asm__ volatile("movw %[user_ds], %%ax\n"
                     "movw %%ax, %%ds\n"
                     "movw %%ax, %%es\n"
                     "movw %%ax, %%fs\n"
                     "movw %%ax, %%gs\n"
                     "movl %[sp], %%esp\n"
                     "pushl %[user_ds]\n"
                     "pushl %[sp]\n"
                     "pushf\n"
                     "popl %%eax\n"
                     "orl %[eflags_if], %%eax\n"
                     "pushl %%eax\n"
                     "pushl %[user_cs]\n"
                     "push %[entry_point]\n"
                     "iret"
                     :
                     : [user_cs] "i"(USER_CS | 3), [user_ds] "i"(USER_DS | 3),
                       [eflags_if] "i"(X86_EFLAGS_IF), [sp] "r"(sp),
                       [entry_point] "r"(entry_point)
                     : "eax");
    UNREACHABLE();

fail_vm:
    ptr_vec_destroy(&envp_ptrs);
    ptr_vec_destroy(&argv_ptrs);
    vm_unref(vm);
    vm_enter(prev_vm);

fail_exe:
    kfree(exe_buf);
    if (file)
        file_close(file);
    string_vec_destroy(envp);
    string_vec_destroy(argv);

    return ret;
}

int task_user_execve(const char* pathname, const char* const* user_argv,
                     const char* const* user_envp) {
    if (!pathname || !user_argv || !user_envp)
        return -EFAULT;

    struct string_vec argv = (struct string_vec){0};
    int rc = string_vec_clone_from_user(&argv, user_argv);
    if (IS_ERR(rc))
        return rc;

    struct string_vec envp = (struct string_vec){0};
    rc = string_vec_clone_from_user(&envp, user_envp);
    if (IS_ERR(rc)) {
        string_vec_destroy(&argv);
        return rc;
    }

    return execve(pathname, &argv, &envp);
}

int task_kernel_execve(const char* pathname, const char* const* argv,
                       const char* const* envp) {
    struct string_vec argv_vec = (struct string_vec){0};
    string_vec_borrow_from_kernel(&argv_vec, argv);

    struct string_vec envp_vec = (struct string_vec){0};
    string_vec_borrow_from_kernel(&envp_vec, envp);

    return execve(pathname, &argv_vec, &envp_vec);
}
