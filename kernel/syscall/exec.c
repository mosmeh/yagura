#include "common/extra.h"
#include <common/string.h>
#include <kernel/api/elf.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stat.h>
#include <kernel/asm_wrapper.h>
#include <kernel/boot_defs.h>
#include <kernel/kmalloc.h>
#include <kernel/mem.h>
#include <kernel/panic.h>
#include <kernel/process.h>

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
        size_t len = strlen(src[i]);
        memcpy(dst_str, src[i], len);
        dst_str[len] = '\0';
        (*dst)[i] = dst_str;
        dst_str += len + 1;
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
        memcpy((void*)*sp, src_strings[i], size);
        (*dst_ptrs)[count - i - 1] = *sp;
    }

    return 0;
}

uintptr_t sys_execve(const char* pathname, char* const argv[],
                     char* const envp[]) {
    if (!pathname || !argv || !envp)
        return -EFAULT;

    fs_node* node = vfs_open(pathname, O_RDWR, 0);
    if (IS_ERR(node))
        return PTR_ERR(node);
    if (!S_ISREG(node->mode))
        return -EACCES;

    file_description desc = {.node = node, .offset = 0};
    void* buf = kmalloc(65536);
    if (!buf)
        return -ENOMEM;
    ssize_t nread = fs_read(&desc, buf, 65536);
    KASSERT(sizeof(Elf32_Ehdr) < (size_t)nread && nread < 65536);

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

    page_directory* prev_pd = mem_current_page_directory();
    page_directory* new_pd = mem_create_page_directory();
    if (IS_ERR(new_pd))
        return PTR_ERR(new_pd);

    current->pd = new_pd;
    mem_switch_page_directory(new_pd);

    // after this point, we have to revert to prev_pd if we want to abort.

    int ret = 0;

    Elf32_Phdr* phdr = (Elf32_Phdr*)((uintptr_t)buf + ehdr->e_phoff);
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
        uintptr_t region_size = region_end - region_start;

        ret = mem_map_to_private_anonymous_region(region_start, region_size,
                                                  MEM_USER | MEM_WRITE);
        if (IS_ERR(ret))
            goto fail;
        memset((void*)region_start, 0, region_size);

        memcpy((void*)phdr->p_vaddr, (void*)((uintptr_t)buf + phdr->p_offset),
               phdr->p_filesz);
    }

    ret = mem_map_to_private_anonymous_region(USER_STACK_BASE, STACK_SIZE,
                                              MEM_WRITE | MEM_USER);
    if (IS_ERR(ret))
        goto fail;

    uintptr_t sp = USER_STACK_TOP;
    memset((void*)USER_STACK_BASE, 0, STACK_SIZE);

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

    cli();

    current->eip = ehdr->e_entry;
    current->esp = current->ebp = sp;
    current->ebx = current->esi = current->edi = 0;

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
    KUNREACHABLE();

fail:
    KASSERT(IS_ERR(ret));
    current->pd = prev_pd;
    mem_switch_page_directory(prev_pd);
    return ret;
}
