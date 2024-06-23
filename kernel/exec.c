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

    for (size_t i = 0; i < strings->count; ++i) {
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
    struct stat stat;
    int rc = vfs_stat_at(current->cwd, pathname, &stat, 0);
    if (IS_ERR(rc))
        return rc;
    if (!S_ISREG(stat.st_mode))
        return -EACCES;
    if ((size_t)stat.st_size < sizeof(Elf32_Ehdr))
        return -ENOEXEC;

    char copied_pathname[PATH_MAX];
    strncpy(copied_pathname, pathname, PATH_MAX);
    const char* exe_basename = basename(copied_pathname);
    char comm[sizeof(current->comm)];
    strlcpy(comm, exe_basename, sizeof(current->comm));

    file_description* desc = vfs_open(pathname, O_RDONLY, 0);
    if (IS_ERR(desc))
        return PTR_ERR(desc);

    void* executable_buf = kmalloc(stat.st_size);
    if (!executable_buf) {
        file_description_close(desc);
        return -ENOMEM;
    }
    ssize_t nread = file_description_read(desc, executable_buf, stat.st_size);
    file_description_close(desc);
    if (IS_ERR(nread)) {
        kfree(executable_buf);
        return nread;
    }

    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)executable_buf;
    if (!IS_ELF(*ehdr) || ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr->e_ident[EI_OSABI] != ELFOSABI_SYSV ||
        ehdr->e_ident[EI_ABIVERSION] != 0 || ehdr->e_machine != EM_386 ||
        ehdr->e_type != ET_EXEC || ehdr->e_version != EV_CURRENT) {
        kfree(executable_buf);
        return -ENOEXEC;
    }

    page_directory* prev_pd = paging_current_page_directory();

    page_directory* new_pd = paging_create_page_directory();
    if (IS_ERR(new_pd)) {
        kfree(executable_buf);
        string_vec_destroy(argv);
        string_vec_destroy(envp);
        return PTR_ERR(new_pd);
    }

    paging_switch_page_directory(new_pd);

    // after this point, we have to revert to prev_pd if we want to abort.

    int ret = 0;
    ptr_vec envp_ptrs = (ptr_vec){0};
    ptr_vec argv_ptrs = (ptr_vec){0};

    Elf32_Phdr* phdr = (Elf32_Phdr*)((uintptr_t)executable_buf + ehdr->e_phoff);
    uintptr_t max_segment_addr = 0;
    for (size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if (phdr->p_type != PT_LOAD)
            continue;
        if (phdr->p_filesz > phdr->p_memsz) {
            ret = -ENOEXEC;
            goto fail;
        }

        uintptr_t region_start = round_down(phdr->p_vaddr, PAGE_SIZE);
        uintptr_t region_end =
            round_up(phdr->p_vaddr + phdr->p_memsz, PAGE_SIZE);
        ret = paging_map_to_free_pages(region_start, region_end - region_start,
                                       PAGE_USER | PAGE_WRITE);
        if (IS_ERR(ret))
            goto fail;

        memset((void*)region_start, 0, phdr->p_vaddr - region_start);
        memcpy((void*)phdr->p_vaddr,
               (void*)((uintptr_t)executable_buf + phdr->p_offset),
               phdr->p_filesz);
        memset((void*)(phdr->p_vaddr + phdr->p_filesz), 0,
               region_end - phdr->p_vaddr - phdr->p_filesz);

        if (!(phdr->p_flags & PF_W))
            paging_set_flags(region_start, region_end - region_start,
                             PAGE_USER);

        if (max_segment_addr < region_end)
            max_segment_addr = region_end;
    }

    uint32_t entry_point = ehdr->e_entry;
    kfree(executable_buf);
    executable_buf = NULL;

    range_allocator vaddr_allocator;
    ret =
        range_allocator_init(&vaddr_allocator, max_segment_addr, KERNEL_VADDR);
    if (IS_ERR(ret))
        goto fail;

    // we keep extra pages before and after stack unmapped to detect stack
    // overflow and underflow by causing page faults
    uintptr_t stack_region =
        range_allocator_alloc(&vaddr_allocator, 2 * PAGE_SIZE + STACK_SIZE);
    if (IS_ERR(stack_region)) {
        ret = stack_region;
        goto fail;
    }
    uintptr_t stack_base = stack_region + PAGE_SIZE;
    ret = paging_map_to_free_pages(stack_base, STACK_SIZE,
                                   PAGE_WRITE | PAGE_USER);
    if (IS_ERR(ret))
        goto fail;

    uintptr_t sp = stack_base + STACK_SIZE;
    memset((void*)stack_base, 0, STACK_SIZE);

    ret = push_strings(&sp, stack_base, &envp_ptrs, envp);
    string_vec_destroy(envp);
    if (IS_ERR(ret))
        goto fail;

    ret = push_strings(&sp, stack_base, &argv_ptrs, argv);
    string_vec_destroy(argv);
    if (IS_ERR(ret))
        goto fail;

    ret = push_value(&sp, stack_base, 0);
    if (IS_ERR(ret))
        goto fail;
    ret = push_ptrs(&sp, stack_base, &envp_ptrs);
    if (IS_ERR(ret))
        goto fail;
    uintptr_t user_envp = sp;
    ptr_vec_destroy(&envp_ptrs);

    ret = push_value(&sp, stack_base, 0);
    if (IS_ERR(ret))
        goto fail;
    ret = push_ptrs(&sp, stack_base, &argv_ptrs);
    if (IS_ERR(ret))
        goto fail;
    uintptr_t user_argv = sp;
    ptr_vec_destroy(&argv_ptrs);

    sp = round_down(sp, 16);

    ret = push_value(&sp, stack_base, user_envp);
    if (IS_ERR(ret))
        goto fail;
    ret = push_value(&sp, stack_base, user_argv);
    if (IS_ERR(ret))
        goto fail;
    ret = push_value(&sp, stack_base, argv->count);
    if (IS_ERR(ret))
        goto fail;
    ret = push_value(&sp, stack_base, 0); // fake return address
    if (IS_ERR(ret))
        goto fail;

    paging_switch_page_directory(prev_pd);
    paging_destroy_current_page_directory();
    paging_switch_page_directory(new_pd);

    cli();

    current->vaddr_allocator = vaddr_allocator;
    current->eip = entry_point;
    current->esp = current->ebp = current->stack_top;
    current->ebx = current->esi = current->edi = 0;
    current->fpu_state = initial_fpu_state;

    strlcpy(current->comm, comm, sizeof(current->comm));

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

fail:
    ASSERT(IS_ERR(ret));

    kfree(executable_buf);
    string_vec_destroy(envp);
    string_vec_destroy(argv);
    ptr_vec_destroy(&envp_ptrs);
    ptr_vec_destroy(&argv_ptrs);

    paging_destroy_current_page_directory();
    paging_switch_page_directory(prev_pd);

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
