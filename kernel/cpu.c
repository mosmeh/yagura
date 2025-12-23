#include <kernel/api/asm/processor-flags.h>
#include <kernel/asm_wrapper.h>
#include <kernel/containers/mpsc.h>
#include <kernel/cpu.h>
#include <kernel/drivers/acpi.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/system.h>

static void set_feature(struct cpu* cpu, int feature) {
    cpu->features[feature >> 5] |= 1U << (feature & 31);
}

bool cpu_has_feature(const struct cpu* cpu, int feature) {
    return cpu->features[feature >> 5] & (1U << (feature & 31));
}

static void detect_features(struct cpu* cpu) {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    uint32_t* vendor_id = (uint32_t*)cpu->vendor_id;
    cpuid(0, &eax, vendor_id, vendor_id + 2, vendor_id + 1);
    if (eax < 1) {
        // CPUID is not supported
        return;
    }

    cpuid(1, &eax, &ebx, &ecx, &edx);
    cpu->apic_id = ebx >> 24;
    cpu->stepping = eax & 0xf;
    cpu->model = (eax >> 4) & 0xf;
    cpu->family = (eax >> 8) & 0xf;
    switch (cpu->family) {
    case 0xf:
        cpu->family += (eax >> 20) & 0xff;
    // falls through
    case 0x6:
        cpu->model += ((eax >> 16) & 0xf) << 4;
    }

#define F(reg, bit, name)                                                      \
    if ((reg) & (1U << (bit)))                                                 \
        set_feature(cpu, X86_FEATURE_##name);

    F(ecx, 0, XMM3)
    F(ecx, 1, PCLMULQDQ)
    F(ecx, 2, DTES64)
    F(ecx, 3, MWAIT)
    F(ecx, 4, DSCPL)
    F(ecx, 5, VMX)
    F(ecx, 6, SMX)
    F(ecx, 7, EST)
    F(ecx, 8, TM2)
    F(ecx, 9, SSSE3)
    F(ecx, 10, CID)
    F(ecx, 11, SDBG)
    F(ecx, 12, FMA)
    F(ecx, 13, CX16)
    F(ecx, 14, XTPR)
    F(ecx, 15, PDCM)
    F(ecx, 17, PCID)
    F(ecx, 18, DCA)
    F(ecx, 19, XMM4_1)
    F(ecx, 20, XMM4_2)
    F(ecx, 21, X2APIC)
    F(ecx, 22, MOVBE)
    F(ecx, 23, POPCNT)
    F(ecx, 24, TSC_DEADLINE_TIMER)
    F(ecx, 25, AES)
    F(ecx, 26, XSAVE)
    F(ecx, 27, OSXSAVE)
    F(ecx, 28, AVX)
    F(ecx, 29, F16C)
    F(ecx, 30, RDRAND)
    F(ecx, 31, HYPERVISOR)

    F(edx, 0, FPU)
    F(edx, 1, VME)
    F(edx, 2, DE)
    F(edx, 3, PSE)
    F(edx, 4, TSC)
    F(edx, 5, MSR)
    F(edx, 6, PAE)
    F(edx, 7, MCE)
    F(edx, 8, CX8)
    F(edx, 9, APIC)
    F(edx, 11, SEP)
    F(edx, 12, MTRR)
    F(edx, 13, PGE)
    F(edx, 14, MCA)
    F(edx, 15, CMOV)
    F(edx, 16, PAT)
    F(edx, 17, PSE36)
    F(edx, 18, PN)
    F(edx, 19, CLFLUSH)
    F(edx, 21, DS)
    F(edx, 22, ACPI)
    F(edx, 23, MMX)
    F(edx, 24, FXSR)
    F(edx, 25, XMM)
    F(edx, 26, XMM2)
    F(edx, 27, SELFSNOOP)
    F(edx, 28, HT)
    F(edx, 29, ACC)
    F(edx, 30, IA64)
    F(edx, 31, PBE)

    cpuid(7, &eax, &ebx, &ecx, &edx);

    F(ebx, 0, FSGSBASE)
    F(ebx, 1, TSC_ADJUST)
    F(ebx, 2, SGX)
    F(ebx, 3, BMI1)
    F(ebx, 4, HLE)
    F(ebx, 5, AVX2)
    F(ebx, 6, FDP_EXCPTN_ONLY)
    F(ebx, 7, SMEP)
    F(ebx, 8, BMI2)
    F(ebx, 9, ERMS)
    F(ebx, 10, INVPCID)
    F(ebx, 11, RTM)
    F(ebx, 12, CQM)
    F(ebx, 13, ZERO_FCS_FDS)
    F(ebx, 14, MPX)
    F(ebx, 15, RDT_A)
    F(ebx, 16, AVX512F)
    F(ebx, 17, AVX512DQ)
    F(ebx, 18, RDSEED)
    F(ebx, 19, ADX)
    F(ebx, 20, SMAP)
    F(ebx, 21, AVX512IFMA)
    F(ebx, 23, CLFLUSHOPT)
    F(ebx, 24, CLWB)
    F(ebx, 25, INTEL_PT)
    F(ebx, 26, AVX512PF)
    F(ebx, 27, AVX512ER)
    F(ebx, 28, AVX512CD)
    F(ebx, 29, SHA_NI)
    F(ebx, 30, AVX512BW)
    F(ebx, 31, AVX512VL)

    F(ecx, 1, AVX512VBMI)
    F(ecx, 2, UMIP)
    F(ecx, 3, PKU)
    F(ecx, 4, OSPKE)
    F(ecx, 5, WAITPKG)
    F(ecx, 6, AVX512_VBMI2)
    F(ecx, 7, SHSTK)
    F(ecx, 8, GFNI)
    F(ecx, 9, VAES)
    F(ecx, 10, VPCLMULQDQ)
    F(ecx, 11, AVX512_VNNI)
    F(ecx, 12, AVX512_BITALG)
    F(ecx, 13, TME)
    F(ecx, 14, AVX512_VPOPCNTDQ)
    F(ecx, 16, LA57)
    F(ecx, 22, RDPID)
    F(ecx, 23, BUS_LOCK_DETECT)
    F(ecx, 25, CLDEMOTE)
    F(ecx, 27, MOVDIRI)
    F(ecx, 28, MOVDIR64B)
    F(ecx, 29, ENQCMD)
    F(ecx, 30, SGX_LC)

    F(edx, 2, AVX512_4VNNIW)
    F(edx, 3, AVX512_4FMAPS)
    F(edx, 4, FSRM)
    F(edx, 8, AVX512_VP2INTERSECT)
    F(edx, 9, SRBDS_CTRL)
    F(edx, 10, MD_CLEAR)
    F(edx, 11, TSX_FORCE_ABORT)
    F(edx, 13, TSX_FORCE_ABORT)
    F(edx, 14, SERIALIZE)
    F(edx, 15, HYBRID_CPU)
    F(edx, 16, TSXLDTRK)
    F(edx, 18, PCONFIG)
    F(edx, 19, ARCH_LBR)
    F(edx, 20, IBT)
    F(edx, 22, AMX_BF16)
    F(edx, 23, AVX512_FP16)
    F(edx, 24, AMX_TILE)
    F(edx, 25, AMX_INT8)
    F(edx, 26, SPEC_CTRL)
    F(edx, 27, INTEL_STIBP)
    F(edx, 28, FLUSH_L1D)
    F(edx, 29, ARCH_CAPABILITIES)
    F(edx, 30, CORE_CAPABILITIES)
    F(edx, 31, SPEC_CTRL_SSBD)

    uint32_t max_ext_func;
    cpuid(0x80000000, &max_ext_func, &ebx, &ecx, &edx);
    if (max_ext_func >= 0x80000001) {
        cpuid(0x80000001, &eax, &ebx, &ecx, &edx);

        F(ecx, 0, LAHF_LM)
        F(ecx, 1, CMP_LEGACY)
        F(ecx, 2, SVM)
        F(ecx, 3, EXTAPIC)
        F(ecx, 4, CR8_LEGACY)
        F(ecx, 5, ABM)
        F(ecx, 6, SSE4A)
        F(ecx, 7, MISALIGNSSE)
        F(ecx, 8, 3DNOWPREFETCH)
        F(ecx, 9, OSVW)
        F(ecx, 10, IBS)
        F(ecx, 11, XOP)
        F(ecx, 12, SKINIT)
        F(ecx, 13, WDT)
        F(ecx, 15, LWP)
        F(ecx, 16, FMA4)
        F(ecx, 17, TCE)
        F(ecx, 19, NODEID_MSR)
        F(ecx, 21, TBM)
        F(ecx, 22, TOPOEXT)
        F(ecx, 23, PERFCTR_CORE)
        F(ecx, 24, PERFCTR_NB)
        F(ecx, 26, BPEXT)
        F(ecx, 27, PTSC)
        F(ecx, 28, PERFCTR_LLC)
        F(ecx, 29, MWAITX)

        F(edx, 11, SYSCALL)
        F(edx, 19, MP)
        F(edx, 20, NX)
        F(edx, 22, MMXEXT)
        F(edx, 23, RDTSCP)
        F(edx, 25, FXSR_OPT)
        F(edx, 26, GBPAGES)
        F(edx, 27, RDTSCP)
        F(edx, 29, LM)
        F(edx, 30, 3DNOWEXT)
        F(edx, 31, 3DNOW)
    }
    if (max_ext_func >= 0x80000004) {
        uint32_t* p = (uint32_t*)cpu->model_name;
        for (int i = 0; i < 3; ++i, p += 4)
            cpuid(0x80000002 + i, p, p + 1, p + 2, p + 3);
    }
    if (max_ext_func >= 0x80000007) {
        cpuid(0x80000007, &eax, &ebx, &ecx, &edx);
        if (edx & (1 << 8)) {
            set_feature(cpu, X86_FEATURE_CONSTANT_TSC);
            set_feature(cpu, X86_FEATURE_NONSTOP_TSC);
        }
    }
    if (max_ext_func >= 0x80000008) {
        cpuid(0x80000008, &eax, &ebx, &ecx, &edx);
        cpu->phys_addr_bits = eax & 0xff;
        cpu->virt_addr_bits = (eax >> 8) & 0xff;
    } else {
        cpu->phys_addr_bits = cpu_has_feature(cpu, X86_FEATURE_PAE) ? 36 : 32;
        cpu->virt_addr_bits = 32;
    }
}

static void init_cpu(struct cpu* cpu) {
    detect_features(cpu);

    if (cpu_has_feature(cpu, X86_FEATURE_XMM)) {
        ASSERT(cpu_has_feature(cpu, X86_FEATURE_FXSR));

        uint32_t cr0 = read_cr0();
        cr0 &= ~X86_CR0_EM;
        cr0 |= X86_CR0_MP;
        write_cr0(cr0);

        write_cr4(read_cr4() | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT);
    }

    if (cpu_has_feature(cpu, X86_FEATURE_PGE))
        write_cr4(read_cr4() | X86_CR4_PGE);

    if (cpu_has_feature(cpu, X86_FEATURE_PAT)) {
        uint64_t pat = rdmsr(0x277);
        pat &= ~((uint64_t)0x7 << 32); // Clear PAT4
        pat |= (uint64_t)1 << 32;      // Set write-combining
        wrmsr(0x277, pat);
    }

    if (cpu_has_feature(cpu, X86_FEATURE_SMEP))
        write_cr4(read_cr4() | X86_CR4_SMEP);
    if (cpu_has_feature(cpu, X86_FEATURE_UMIP))
        write_cr4(read_cr4() | X86_CR4_UMIP);
}

static struct cpu bsp;
size_t num_cpus = 1;
struct cpu* cpus[MAX_NUM_CPUS] = {&bsp};
static struct mpsc* msg_pool;

void cpu_init(void) { init_cpu(cpu_get_current()); }

void cpu_init_smp(void) {
    const struct acpi* acpi = acpi_get();
    ASSERT(acpi);
    for (const struct local_apic** p = acpi->local_apics; *p; ++p) {
        if (!((*p)->flags & ACPI_LOCAL_APIC_ENABLED))
            continue;

        uint8_t apic_id = (*p)->apic_id;
        if (apic_id == bsp.apic_id)
            continue;

        for (size_t i = 0; i < num_cpus; ++i)
            ASSERT(cpus[i]->apic_id != apic_id);
        ASSERT(num_cpus < ARRAY_SIZE(cpus));

        struct cpu* cpu = kmalloc(sizeof(struct cpu));
        ASSERT(cpu);
        *cpu = (struct cpu){.apic_id = apic_id};
        cpus[num_cpus++] = cpu;
    }

    msg_pool = mpsc_create(num_cpus);
    ASSERT_PTR(msg_pool);
    for (size_t i = 0; i < num_cpus; ++i) {
        struct cpu* cpu = cpus[i];
        cpu->queued_msgs = mpsc_create(num_cpus);
        ASSERT(cpu->queued_msgs);

        struct ipi_message* msg = kmalloc(sizeof(struct ipi_message));
        ASSERT(msg);
        *msg = (struct ipi_message){0};
        ASSERT(mpsc_enqueue(msg_pool, msg));
    }
}

uint8_t cpu_get_id(void) {
    uint32_t id;
    __asm__ volatile("lsl %[selector], %[id]"
                     : [id] "=r"(id)
                     : [selector] "r"(CPU_ID_SELECTOR));
    ASSERT(id < num_cpus);
    return id;
}

struct cpu* cpu_get_bsp(void) { return &bsp; }

struct cpu* cpu_get_current(void) {
    ASSERT(!interrupts_enabled());
    struct cpu* cpu = cpus[cpu_get_id()];
    ASSERT(cpu);
    return cpu;
}

void cpu_pause(void) {
    cpu_process_messages();
    pause();
}

struct ipi_message* cpu_alloc_message(void) {
    for (;;) {
        struct ipi_message* msg = mpsc_dequeue(msg_pool);
        if (msg) {
            ASSERT(refcount_get(&msg->refcount) == 0);
            return msg;
        }
        cpu_pause();
    }
}

void cpu_free_message(struct ipi_message* msg) {
    ASSERT(msg);
    ASSERT(refcount_get(&msg->refcount) == 0);
    while (!mpsc_enqueue(msg_pool, msg))
        cpu_pause();
}

void cpu_broadcast_message_queued(struct ipi_message* msg, bool eager) {
    bool int_flag = push_cli();
    uint8_t cpu_id = cpu_get_id();
    for (size_t i = 0; i < num_cpus; ++i) {
        if (i == cpu_id)
            continue;
        while (!mpsc_enqueue(cpus[i]->queued_msgs, msg))
            cpu_pause();
    }
    pop_cli(int_flag);
    if (eager)
        lapic_broadcast_ipi();
}

void cpu_broadcast_message_coalesced(unsigned int type, bool eager) {
    for (size_t i = 0; i < num_cpus; ++i) {
        struct cpu* cpu = cpus[i];
        cpu->coalesced_msgs |= type;
    }
    if (eager)
        lapic_broadcast_ipi();
}

void cpu_unicast_message_queued(struct cpu* dest, struct ipi_message* msg,
                                bool eager) {
    while (!mpsc_enqueue(dest->queued_msgs, msg))
        cpu_pause();
    if (eager)
        lapic_unicast_ipi(dest->apic_id);
}

void cpu_unicast_message_coalesced(struct cpu* dest, unsigned int type,
                                   bool eager) {
    dest->coalesced_msgs |= type;
    if (eager)
        lapic_unicast_ipi(dest->apic_id);
}

static void handle_halt(struct ipi_message* msg) {
    (void)msg;
    cli();
    for (;;)
        hlt();
}

static void handle_flush_tlb(struct ipi_message* msg) {
    (void)msg;
    flush_tlb();
}

static void handle_flush_tlb_range(struct ipi_message* msg) {
    ASSERT(msg);
    size_t virt_addr = msg->flush_tlb_range.virt_addr;
    size_t size = msg->flush_tlb_range.size;
    for (uintptr_t addr = virt_addr; addr < virt_addr + size; addr += PAGE_SIZE)
        flush_tlb_single(addr);
}

static void (*const message_handlers[])(struct ipi_message*) = {
    [IPI_MESSAGE_HALT] = handle_halt,
    [IPI_MESSAGE_FLUSH_TLB] = handle_flush_tlb,
    [IPI_MESSAGE_FLUSH_TLB_RANGE] = handle_flush_tlb_range,
};

void cpu_process_messages(void) {
    if (!smp_active)
        return;

    bool int_flag = push_cli();
    struct cpu* cpu = cpu_get_current();
    for (;;) {
        int bit = __builtin_ffs(cpu->coalesced_msgs);
        if (bit == 0)
            break;
        unsigned type = 1U << (bit - 1);
        cpu->coalesced_msgs &= ~type;
        message_handlers[type](NULL);
    }
    for (;;) {
        struct ipi_message* msg = mpsc_dequeue(cpu->queued_msgs);
        if (!msg)
            break;
        message_handlers[msg->type](msg);
        refcount_dec(&msg->refcount);
    }
    pop_cli(int_flag);
}
