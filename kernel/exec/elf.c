#include "private.h"
#include <common/integer.h>
#include <kernel/api/elf.h>
#include <kernel/cpu.h>
#include <kernel/memory/safe_string.h>
#include <kernel/memory/vm.h>
#include <kernel/system.h>
#include <kernel/time.h>

NODISCARD static int validate_ehdr(const Elf32_Ehdr* ehdr) {
    if (!IS_ELF(*ehdr) || ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr->e_ident[EI_ABIVERSION] != 0 || ehdr->e_machine != EM_386 ||
        ehdr->e_version != EV_CURRENT ||
        ehdr->e_phentsize != sizeof(Elf32_Phdr))
        return -ENOEXEC;

    switch (ehdr->e_ident[EI_OSABI]) {
    case ELFOSABI_NONE:
    case ELFOSABI_GNU:
        break;
    default:
        return -ENOEXEC;
    }

    switch (ehdr->e_type) {
    case ET_EXEC:
    case ET_DYN:
        break;
    default:
        return -ENOEXEC;
    }

    return 0;
}

NODISCARD
static int load_segments(struct loader* loader, void** out_phdr_addr) {
    const Elf32_Ehdr* ehdr = (const void*)loader->image.data;
    const Elf32_Phdr* phdr = (const void*)(loader->image.data + ehdr->e_phoff);
    void* phdr_addr = NULL;
    for (size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if (phdr->p_type != PT_LOAD)
            continue;
        if (phdr->p_filesz > phdr->p_memsz)
            return -ENOEXEC;

        if (phdr->p_offset <= ehdr->e_phoff &&
            ehdr->e_phoff < phdr->p_offset + phdr->p_filesz)
            phdr_addr = (void*)(ehdr->e_phoff - phdr->p_offset + phdr->p_vaddr);

        if (phdr->p_filesz > 0) {
            uintptr_t start = ROUND_DOWN(phdr->p_vaddr, PAGE_SIZE);
            size_t npages =
                DIV_CEIL(phdr->p_filesz + (phdr->p_vaddr - start), PAGE_SIZE);
            struct vm_region* region =
                vm_alloc_at(loader->vm, (void*)start, npages);
            if (IS_ERR(ASSERT(region)))
                return PTR_ERR(region);

            unsigned vm_flags = VM_USER;
            if (phdr->p_flags & PF_R)
                vm_flags |= VM_READ;
            if (phdr->p_flags & PF_W)
                vm_flags |= VM_WRITE;
            int rc = vm_region_set_flags(region, 0, npages, vm_flags, ~0);
            if (IS_ERR(rc))
                return rc;

            size_t offset_bytes = phdr->p_offset - (phdr->p_vaddr - start);
            vm_region_set_obj(region, loader->image.obj,
                              offset_bytes >> PAGE_SHIFT);

            uintptr_t zero_start = phdr->p_vaddr + phdr->p_filesz;
            uintptr_t zero_end = ROUND_UP(zero_start, PAGE_SIZE);
            if (zero_start < zero_end && (vm_flags & VM_WRITE)) {
                // Zero the remaining bytes in the last page
                if (clear_user((void*)zero_start, zero_end - zero_start))
                    return -EFAULT;
            }
        }

        // Map anonymous pages for the BSS section
        uintptr_t zero_start =
            ROUND_UP(phdr->p_vaddr + phdr->p_filesz, PAGE_SIZE);
        uintptr_t zero_end = ROUND_UP(phdr->p_vaddr + phdr->p_memsz, PAGE_SIZE);
        if (zero_start < zero_end) {
            size_t npages = (zero_end - zero_start) >> PAGE_SHIFT;
            struct vm_region* region =
                vm_alloc_at(loader->vm, (void*)zero_start, npages);
            if (IS_ERR(ASSERT(region)))
                return PTR_ERR(region);

            // Linux sets READ | WRITE | EXEC for anonymous tail pages
            int rc = vm_region_set_flags(region, 0, npages,
                                         VM_READ | VM_WRITE | VM_USER, ~0);
            if (IS_ERR(rc))
                return rc;

            struct vm_obj* anon FREE(vm_obj) = anon_create();
            if (IS_ERR(ASSERT(anon)))
                return PTR_ERR(anon);
            vm_region_set_obj(region, anon, 0);
        }
    }
    if (out_phdr_addr)
        *out_phdr_addr = phdr_addr;
    return 0;
}

NODISCARD
static int populate_stack(struct loader* loader, const Elf32_Ehdr* ehdr,
                          void* phdr_addr) {
    loader->stack_ptr = (void*)ROUND_DOWN((uintptr_t)loader->stack_ptr, 16);

    unsigned char* random;
    {
        unsigned char buf[16] = {0};
        ssize_t nread = random_get(buf, sizeof(buf));
        if (IS_ERR(nread))
            return nread;
        random = loader->stack_ptr - sizeof(buf);
        if (random < loader->stack_base)
            return -E2BIG;
        if (copy_to_user(random, buf, sizeof(buf)))
            return -EFAULT;
    }
    loader->stack_ptr = random;

    Elf32_auxv_t auxv[] = {
        {AT_PHDR, {(uint32_t)phdr_addr}},
        {AT_PHENT, {ehdr->e_phentsize}},
        {AT_PHNUM, {ehdr->e_phnum}},
        {AT_PAGESZ, {PAGE_SIZE}},
        {AT_ENTRY, {ehdr->e_entry}},
        {AT_UID, {0}},
        {AT_EUID, {0}},
        {AT_GID, {0}},
        {AT_EGID, {0}},
        {AT_HWCAP, {cpu_get_bsp()->features[0]}},
        {AT_CLKTCK, {CLK_TCK}},
        {AT_SECURE, {0}},
        {AT_RANDOM, {(uint32_t)random}},
        {AT_EXECFN, {(uint32_t)loader->arg_start}},
        {AT_NULL, {0}},
    };
    loader->stack_ptr -= sizeof(auxv);
    if (loader->stack_ptr < loader->stack_base)
        return -E2BIG;
    if (copy_to_user(loader->stack_ptr, auxv, sizeof(auxv)))
        return -EFAULT;

    uintptr_t* cursor = (void*)loader->stack_ptr;
    cursor -= loader->envc + 1; // envp + NULL
    cursor -= loader->argc + 1; // argv + NULL
    --cursor;                   // argc

    loader->stack_ptr = (void*)cursor;
    if (loader->stack_ptr < loader->stack_base)
        return -E2BIG;

    char* null_ptr = NULL;

    if (copy_to_user(cursor++, &loader->argc, sizeof(size_t)))
        return -EFAULT;

    char* arg_ptr = loader->arg_start;
    for (size_t i = 0; i < loader->argc; ++i) {
        if (copy_to_user(cursor++, &arg_ptr, sizeof(char*)))
            return -EFAULT;
        ssize_t len = strnlen_user(arg_ptr, ARG_MAX);
        if (IS_ERR(len))
            return PTR_ERR(len);
        if (len >= ARG_MAX)
            return -E2BIG;
        arg_ptr += len + 1;
    }
    if (copy_to_user(cursor++, &null_ptr, sizeof(char*)))
        return -EFAULT;

    char* env_ptr = loader->env_start;
    for (size_t i = 0; i < loader->envc; ++i) {
        if (copy_to_user(cursor++, &env_ptr, sizeof(char*)))
            return -EFAULT;
        ssize_t len = strnlen_user(env_ptr, ARG_MAX);
        if (IS_ERR(len))
            return PTR_ERR(len);
        if (len >= ARG_MAX)
            return -E2BIG;
        env_ptr += len + 1;
    }
    if (copy_to_user(cursor++, &null_ptr, sizeof(char*)))
        return -EFAULT;

    return 0;
}

int elf_load(struct loader* loader) {
    const Elf32_Ehdr* ehdr = (const void*)loader->image.data;
    int rc = validate_ehdr(ehdr);
    if (IS_ERR(rc))
        return rc;

    void* phdr_addr = NULL;
    rc = load_segments(loader, &phdr_addr);
    if (IS_ERR(rc))
        return rc;

    loader->entry_point = (void*)ehdr->e_entry;

    rc = populate_stack(loader, ehdr, phdr_addr);
    if (IS_ERR(rc))
        return rc;

    loader->commit = true;
    return rc;
}
