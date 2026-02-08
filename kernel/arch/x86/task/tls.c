#include <common/string.h>
#include <kernel/api/x86/asm/ldt.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/task.h>

static int get_tls_entry(struct user_desc* inout_u_info) {
    struct user_desc* u = inout_u_info;
    int index = u->entry_number;
    if (index < GDT_ENTRY_TLS_MIN ||
        GDT_ENTRY_TLS_MIN + NUM_GDT_TLS_ENTRIES <= index)
        return -EINVAL;

    const struct gdt_segment* s =
        current->arch.tls + (index - GDT_ENTRY_TLS_MIN);
    u->base_addr = s->base_lo | (s->base_mid << 16) | (s->base_hi << 24);
    u->limit = s->limit_lo | (s->limit_hi << 16);
    u->seg_32bit = s->operation_size32;
    u->contents = s->type >> 2;
    u->read_exec_only = !(s->type & 2);
    u->limit_in_pages = s->granularity;
    u->seg_not_present = !s->segment_present;
    u->useable = s->avl;
    return 0;
}

static bool is_user_desc_empty(const struct user_desc* u) {
    if (u->base_addr || u->limit || u->seg_32bit || u->contents ||
        u->limit_in_pages || u->useable)
        return false;
    if (!u->read_exec_only && !u->seg_not_present)
        return true;
    if (u->read_exec_only && u->seg_not_present)
        return true;
    return false;
}

static bool is_user_desc_valid(const struct user_desc* u) {
    if (is_user_desc_empty(u))
        return true;
    if (!u->seg_32bit)
        return false;
    if (u->contents > 1)
        return false;
    if (u->seg_not_present)
        return false;
    return true;
}

NODISCARD
static int set_tls_entry(struct task* task, const struct user_desc* u) {
    int index = u->entry_number;
    if (index < GDT_ENTRY_TLS_MIN ||
        GDT_ENTRY_TLS_MIN + NUM_GDT_TLS_ENTRIES <= index)
        return -EINVAL;

    struct gdt_segment* s = task->arch.tls + (index - GDT_ENTRY_TLS_MIN);
    if (is_user_desc_empty(u)) {
        *s = (struct gdt_segment){0};
        return 0;
    }

    s->base_lo = u->base_addr & 0xffff;
    s->base_mid = (u->base_addr >> 16) & 0xff;
    s->base_hi = (u->base_addr >> 24) & 0xff;
    s->limit_lo = u->limit & 0xffff;
    s->limit_hi = (u->limit >> 16) & 0xf;

    s->type = (!u->read_exec_only << 1) | (u->contents << 2) | 1;
    s->descriptor_type = 1;
    s->dpl = 3;
    s->segment_present = !u->seg_not_present;
    s->avl = u->useable;
    s->operation_size64 = 0;
    s->operation_size32 = u->seg_32bit;
    s->granularity = u->limit_in_pages;

    return 0;
}

long sys_get_thread_area(struct user_desc* user_u_info) {
    struct user_desc u_info;
    if (copy_from_user(&u_info, user_u_info, sizeof(struct user_desc)))
        return -EFAULT;
    int rc = get_tls_entry(&u_info);
    if (IS_ERR(rc))
        return rc;
    if (copy_to_user(user_u_info, &u_info, sizeof(struct user_desc)))
        return -EFAULT;
    return 0;
}

static int find_free_tls_entry(void) {
    for (size_t i = 0; i < ARRAY_SIZE(current->arch.tls); ++i) {
        const struct gdt_segment* s = current->arch.tls + i;
        if (s->low || s->high)
            continue;
        return i + GDT_ENTRY_TLS_MIN;
    }
    return -ESRCH;
}

long sys_set_thread_area(struct user_desc* user_u_info) {
    struct user_desc u_info;
    if (copy_from_user(&u_info, user_u_info, sizeof(struct user_desc)))
        return -EFAULT;

    if (!is_user_desc_valid(&u_info))
        return -EINVAL;

    int index = u_info.entry_number;
    bool should_alloc = index == -1;
    if (should_alloc) {
        index = find_free_tls_entry();
        if (IS_ERR(index))
            return index;
    }
    u_info.entry_number = index;

    {
        SCOPED_DISABLE_INTERRUPTS();

        int rc = set_tls_entry(current, &u_info);
        if (IS_ERR(rc))
            return rc;

        memcpy(cpu_get_current()->arch.gdt + GDT_ENTRY_TLS_MIN,
               current->arch.tls, sizeof(current->arch.tls));
    }

    if (should_alloc) {
        if (copy_to_user((unsigned char*)user_u_info +
                             offsetof(struct user_desc, entry_number),
                         &u_info.entry_number, sizeof(u_info.entry_number)))
            return -EFAULT;
    }

    return 0;
}

int arch_set_tls(struct task* task, void* user_tls) {
#ifdef ARCH_I386
    struct user_desc u_info;
    if (copy_from_user(&u_info, user_tls, sizeof(struct user_desc)))
        return -EFAULT;
    if (!is_user_desc_valid(&u_info))
        return -EINVAL;
    return set_tls_entry(task, &u_info);
#endif
#ifdef ARCH_X86_64
    if (!is_user_address(user_tls))
        return -EPERM;
    task->arch.fs_base = (unsigned long)user_tls;
    return 0;
#endif
}
