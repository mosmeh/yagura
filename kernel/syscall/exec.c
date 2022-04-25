#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/elf.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stat.h>
#include <kernel/asm_wrapper.h>
#include <kernel/boot_defs.h>
#include <kernel/kmalloc.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <string.h>

static ssize_t copy_strings(char** dst[], char* const src[]) {
    size_t count = 0;
    size_t total_size = 0;
    for (char* const* it = src; *it; ++it) {
        total_size += strlen(*it) + 1;
        ++count;
    }

    if (count == 0) {
        *dst = NULL;
        return 0;
    }

    char* buf = kmalloc(total_size);
    if (!buf)
        return -ENOMEM;

    char* dst_str = buf;
    *dst = kmalloc(count * sizeof(char*));

    for (size_t i = 0; i < count; ++i) {
        size_t size = strlen(src[i]) + 1;
        strlcpy(dst_str, src[i], size);
        (*dst)[i] = dst_str;
        dst_str += size;
    }

    return count;
}

static void push_value(uintptr_t* sp, uintptr_t value) {
    *sp -= sizeof(uintptr_t);
    *(uintptr_t*)*sp = value;
}

static int push_strings(uintptr_t* sp, uintptr_t** dst_ptrs,
                        char* const src_strings[], size_t count) {
    if (count == 0) {
        *dst_ptrs = NULL;
        return 0;
    }

    *dst_ptrs = kmalloc(count * sizeof(uintptr_t));
    if (!*dst_ptrs)
        return -ENOMEM;

    for (size_t i = 0; i < count; ++i) {
        size_t size = strlen(src_strings[i]) + 1;
        *sp -= next_power_of_two(size);
        strlcpy((char*)*sp, src_strings[i], size);
        (*dst_ptrs)[count - i - 1] = *sp;
    }

    return 0;
}

uintptr_t sys_execve(const char* pathname, char* const argv[],
                     char* const envp[]) {
    if (!pathname || !argv || !envp)
        return -EFAULT;

    struct stat stat;
    int rc = vfs_stat(pathname, &stat);
    if (IS_ERR(rc))
        return rc;
    if (!S_ISREG(stat.st_mode))
        return -EACCES;
    if ((size_t)stat.st_size < sizeof(Elf32_Ehdr))
        return -ENOEXEC;

    file_description* desc = vfs_open(pathname, O_RDONLY, 0);
    if (IS_ERR(desc))
        return PTR_ERR(desc);

    void* buf = kmalloc(stat.st_size);
    if (!buf)
        return -ENOMEM;
    ssize_t nread = fs_read(desc, buf, stat.st_size);
    if (IS_ERR(nread))
        return nread;

    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)buf;
    if (!IS_ELF(*ehdr) || ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr->e_ident[EI_OSABI] != ELFOSABI_SYSV ||
        ehdr->e_ident[EI_ABIVERSION] != 0 || ehdr->e_machine != EM_386 ||
        ehdr->e_type != ET_EXEC || ehdr->e_version != EV_CURRENT)
        return -ENOEXEC;

    // after switching page directory we will no longer be able to access
    // argv and envp, so we copy them here.
    char** copied_argv;
    ssize_t argc = copy_strings(&copied_argv, argv);
    if (IS_ERR(argc))
        return argc;

    char** copied_envp;
    ssize_t num_envp = copy_strings(&copied_envp, envp);
    if (IS_ERR(num_envp))
        return num_envp;

    page_directory* prev_pd = memory_current_page_directory();

    page_directory* new_pd = memory_create_page_directory();
    if (IS_ERR(new_pd))
        return PTR_ERR(new_pd);

    current->pd = new_pd;
    memory_switch_page_directory(new_pd);

    // after this point, we have to revert to prev_pd if we want to abort.

    int ret = 0;

    Elf32_Phdr* phdr = (Elf32_Phdr*)((uintptr_t)buf + ehdr->e_phoff);
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
        ret = memory_map_to_anonymous_region(region_start,
                                             region_end - region_start,
                                             MEMORY_USER | MEMORY_WRITE);
        if (IS_ERR(ret))
            goto fail;

        memset((void*)region_start, 0, phdr->p_vaddr - region_start);
        memcpy((void*)phdr->p_vaddr, (void*)((uintptr_t)buf + phdr->p_offset),
               phdr->p_filesz);
        memset((void*)(phdr->p_vaddr + phdr->p_filesz), 0,
               region_end - phdr->p_vaddr - phdr->p_filesz);

        if (max_segment_addr < region_end)
            max_segment_addr = region_end;
    }

    range_allocator vaddr_allocator;
    range_allocator_init(&vaddr_allocator, max_segment_addr, KERNEL_VADDR);

    // we keep extra pages before and after stack unmapped to detect stack
    // overflow and underflow by causing page faults
    uintptr_t stack_region =
        range_allocator_alloc(&vaddr_allocator, 2 * PAGE_SIZE + STACK_SIZE);
    if (IS_ERR(stack_region)) {
        ret = stack_region;
        goto fail;
    }
    uintptr_t stack_base = stack_region + PAGE_SIZE;
    ret = memory_map_to_anonymous_region(stack_base, STACK_SIZE,
                                         MEMORY_WRITE | MEMORY_USER);
    if (IS_ERR(ret))
        goto fail;

    uintptr_t sp = stack_base + STACK_SIZE;
    memset((void*)stack_base, 0, STACK_SIZE);

    uintptr_t* envp_ptrs;
    ret = push_strings(&sp, &envp_ptrs, copied_envp, num_envp);
    if (IS_ERR(ret))
        goto fail;

    uintptr_t* argv_ptrs;
    ret = push_strings(&sp, &argv_ptrs, copied_argv, argc);
    if (IS_ERR(ret))
        goto fail;

    push_value(&sp, 0);
    for (ssize_t i = 0; i < num_envp; ++i)
        push_value(&sp, envp_ptrs[i]);
    uintptr_t user_envp = sp;

    push_value(&sp, 0);
    for (ssize_t i = 0; i < argc; ++i)
        push_value(&sp, argv_ptrs[i]);
    uintptr_t user_argv = sp;

    sp = round_down(sp, 16);

    push_value(&sp, user_envp);
    push_value(&sp, user_argv);
    push_value(&sp, argc);
    push_value(&sp, 0); // fake return address

    range_allocator_destroy(&current->vaddr_allocator);
    current->vaddr_allocator = vaddr_allocator;

    cli();

    current->eip = ehdr->e_entry;
    current->esp = current->ebp = current->stack_top;
    current->ebx = current->esi = current->edi = 0;
    current->fpu_state = initial_fpu_state;

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
                     "r"(ehdr->e_entry)
                     : "eax");
    UNREACHABLE();

fail:
    ASSERT(IS_ERR(ret));
    current->pd = prev_pd;
    memory_switch_page_directory(prev_pd);
    return ret;
}
