#include "private.h"
#include <arch/elf.h>
#include <common/integer.h>
#include <kernel/api/elf.h>
#include <kernel/cpu.h>
#include <kernel/memory/safe_string.h>
#include <kernel/memory/vm.h>
#include <kernel/system.h>
#include <kernel/time.h>

#define INVALID_ADDR ((void*)(-1))

NODISCARD static int validate_ehdr(const elf_ehdr_t* ehdr) {
    if (!IS_ELF(*ehdr) || ehdr->e_ident[EI_CLASS] != ELF_CLASS ||
        ehdr->e_ident[EI_DATA] != ELF_DATA ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr->e_ident[EI_ABIVERSION] != 0 || ehdr->e_machine != ELF_ARCH ||
        ehdr->e_version != EV_CURRENT ||
        ehdr->e_phentsize != sizeof(elf_phdr_t))
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

NODISCARD static const char* find_interp(const struct exec_image* image) {
    const elf_ehdr_t* ehdr = (const void*)image->data;
    const elf_phdr_t* phdr = (const void*)(image->data + ehdr->e_phoff);
    for (size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if (phdr->p_type != PT_INTERP)
            continue;
        if (phdr->p_filesz == 0 || phdr->p_filesz > PATH_MAX)
            return ERR_PTR(-ENOEXEC);
        const char* interp = (const void*)(image->data + phdr->p_offset);
        if (interp[phdr->p_filesz - 1] != 0)
            return ERR_PTR(-ENOEXEC);
        return interp;
    }
    return NULL;
}

NODISCARD
static int load_segments(struct vm* vm, const struct exec_image* image,
                         bool fixed, size_t* inout_base, void** out_phdr_addr) {
    const elf_ehdr_t* ehdr = (const void*)image->data;
    const elf_phdr_t* phdr = (const void*)(image->data + ehdr->e_phoff);

    unsigned char* base_addr = INVALID_ADDR;
    unsigned char* phdr_addr = INVALID_ADDR;

    for (size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if (phdr->p_type != PT_LOAD)
            continue;
        if (phdr->p_filesz > phdr->p_memsz)
            return -ENOEXEC;

        // For the first segment:
        //  - If fixed is true, use the specified virtual address
        //  - If fixed is false, let the VM choose the address and set base_addr
        // For subsequent segments:
        //  - Calculate the virtual address relative to base_addr

        uintptr_t vaddr = phdr->p_vaddr;
        if (base_addr == INVALID_ADDR)
            vaddr += inout_base ? *inout_base : 0;
        else
            vaddr += (uintptr_t)base_addr;

        if (phdr->p_filesz > 0) {
            size_t page_offset = vaddr % PAGE_SIZE;
            size_t npages = DIV_CEIL(phdr->p_filesz + page_offset, PAGE_SIZE);

            struct vm_region* region;
            uintptr_t region_start;
            if (fixed || base_addr != INVALID_ADDR) {
                region_start = ROUND_DOWN(vaddr, PAGE_SIZE);
                region = vm_alloc_at(vm, (void*)region_start, npages);
                if (IS_ERR(ASSERT(region)))
                    return PTR_ERR(region);
            } else {
                // Let the VM choose the address
                region = vm_alloc(vm, npages);
                if (IS_ERR(ASSERT(region)))
                    return PTR_ERR(region);
                region_start = (uintptr_t)vm_region_to_virt(region);
                vaddr = region_start + page_offset;
            }
            if (base_addr == INVALID_ADDR) {
                base_addr = (void*)(region_start -
                                    ROUND_DOWN(phdr->p_vaddr, PAGE_SIZE));
            }

            unsigned vm_flags = VM_USER;
            if (phdr->p_flags & PF_R)
                vm_flags |= VM_READ;
            if (phdr->p_flags & PF_W)
                vm_flags |= VM_WRITE;
            int rc = vm_region_set_flags(region, 0, npages, vm_flags, ~0);
            if (IS_ERR(rc))
                return rc;

            size_t offset_bytes = phdr->p_offset - page_offset;
            vm_region_set_obj(region, image->obj, offset_bytes >> PAGE_SHIFT);

            uintptr_t zero_start = vaddr + phdr->p_filesz;
            uintptr_t zero_end = ROUND_UP(zero_start, PAGE_SIZE);
            if (zero_start < zero_end && (vm_flags & VM_WRITE)) {
                // Zero the remaining bytes in the last page
                if (clear_user((void*)zero_start, zero_end - zero_start))
                    return -EFAULT;
            }
        }

        if (phdr->p_offset <= ehdr->e_phoff &&
            ehdr->e_phoff < phdr->p_offset + phdr->p_filesz)
            phdr_addr = (void*)(ehdr->e_phoff - phdr->p_offset + vaddr);

        // Map anonymous pages for the BSS section
        uintptr_t zero_start = ROUND_UP(vaddr + phdr->p_filesz, PAGE_SIZE);
        uintptr_t zero_end = ROUND_UP(vaddr + phdr->p_memsz, PAGE_SIZE);
        if (zero_start < zero_end) {
            if (base_addr == INVALID_ADDR) {
                // We encountered BSS before any file-backed PT_LOAD segment
                return -ENOEXEC;
            }

            size_t npages = (zero_end - zero_start) >> PAGE_SHIFT;
            struct vm_region* region =
                vm_alloc_at(vm, (void*)zero_start, npages);
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

    if (base_addr == INVALID_ADDR || phdr_addr == INVALID_ADDR)
        return -ENOEXEC;

    if (inout_base)
        *inout_base = (size_t)base_addr;
    if (out_phdr_addr)
        *out_phdr_addr = phdr_addr;
    return 0;
}

NODISCARD static ssize_t load_interp(struct loader* loader,
                                     const struct exec_image* image) {
    const elf_ehdr_t* ehdr = (const void*)image->data;
    int rc = validate_ehdr(ehdr);
    if (IS_ERR(rc))
        return rc;

    size_t base = 0;
    rc = load_segments(loader->vm, image, false, &base, NULL);
    if (IS_ERR(rc))
        return rc;

    loader->entry_point = (void*)(ehdr->e_entry + base);
    return base;
}

NODISCARD
static int populate_stack(struct loader* loader, const elf_ehdr_t* ehdr,
                          void* phdr_addr, size_t interp_base,
                          void* entry_point) {
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

    elf_auxv_t auxv[] = {
        {AT_PHDR, {(uintptr_t)phdr_addr}},
        {AT_PHENT, {ehdr->e_phentsize}},
        {AT_PHNUM, {ehdr->e_phnum}},
        {AT_PAGESZ, {PAGE_SIZE}},
        {AT_BASE, {interp_base}},
        {AT_ENTRY, {(uintptr_t)entry_point}},
        {AT_UID, {0}},
        {AT_EUID, {0}},
        {AT_GID, {0}},
        {AT_EGID, {0}},
        {AT_HWCAP, {arch_cpu_get_hwcap()}},
        {AT_CLKTCK, {CLK_TCK}},
        {AT_SECURE, {0}},
        {AT_RANDOM, {(uintptr_t)random}},
        {AT_EXECFN, {(uintptr_t)loader->execfn}},
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
    const elf_ehdr_t* ehdr = (const void*)loader->image.data;
    int rc = validate_ehdr(ehdr);
    if (IS_ERR(rc))
        return rc;

    const char* interp = find_interp(&loader->image);
    if (IS_ERR(interp))
        return PTR_ERR(interp);

    void* phdr_addr = NULL;
    size_t exec_base = 0;
    bool exec_fixed = false;
    switch (ehdr->e_type) {
    case ET_EXEC:
        exec_fixed = true;
        break;
    case ET_DYN:
        if (interp) {
            exec_base = ELF_ET_DYN_BASE;
            exec_fixed = true;
        }
        break;
    default:
        return -ENOEXEC;
    }
    rc = load_segments(loader->vm, &loader->image, exec_fixed, &exec_base,
                       &phdr_addr);
    if (IS_ERR(rc))
        return rc;

    void* entry_point = (void*)(ehdr->e_entry + exec_base);
    loader->entry_point = entry_point;

    size_t interp_base = 0;
    if (interp) {
        struct exec_image interp_image = {0};
        rc = exec_image_load(&interp_image, interp);
        if (IS_ERR(rc))
            return rc;
        ssize_t base = load_interp(loader, &interp_image);
        exec_image_unload(&interp_image);
        if (IS_ERR(base))
            return base;
        interp_base = base;
    }

    rc = populate_stack(loader, ehdr, phdr_addr, interp_base, entry_point);
    if (IS_ERR(rc))
        return rc;

    loader->commit = true;
    return rc;
}
