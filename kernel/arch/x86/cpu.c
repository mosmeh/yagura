#include <common/limits.h>
#include <kernel/api/x86/asm/processor-flags.h>
#include <kernel/arch/x86/interrupts/interrupts.h>
#include <kernel/arch/x86/msr.h>
#include <kernel/containers/vec.h>
#include <kernel/cpu.h>
#include <kernel/drivers/acpi.h>
#include <kernel/task/task.h>

// NOLINTBEGIN(readability-non-const-parameter)
static void cpuid(uint32_t function, uint32_t* eax, uint32_t* ebx,
                  uint32_t* ecx, uint32_t* edx) {
    // NOLINTEND(readability-non-const-parameter)
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(function), "c"(0));
}

static void set_feature(struct arch_cpu* arch, int feature) {
    arch->features[feature / LONG_WIDTH] |= 1UL << (feature & (LONG_WIDTH - 1));
}

bool cpu_has_feature(const struct cpu* cpu, int feature) {
    return cpu->arch.features[feature / LONG_WIDTH] &
           (1UL << (feature & (LONG_WIDTH - 1)));
}

unsigned long arch_cpu_get_hwcap(void) { return cpu_get_bsp()->arch.hwcap; }

static void detect_features(struct cpu* cpu) {
    struct arch_cpu* arch = &cpu->arch;

    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    uint32_t* vendor_id = (uint32_t*)arch->vendor_id;
    cpuid(0, &eax, vendor_id, vendor_id + 2, vendor_id + 1);
    if (eax < 1) {
        // CPUID is not supported
        return;
    }

    cpuid(1, &eax, &ebx, &ecx, &edx);
    arch->apic_id = ebx >> 24;
    arch->stepping = eax & 0xf;
    arch->model = (eax >> 4) & 0xf;
    arch->family = (eax >> 8) & 0xf;
    switch (arch->family) {
    case 0xf:
        arch->family += (eax >> 20) & 0xff;
    // falls through
    case 0x6:
        arch->model += ((eax >> 16) & 0xf) << 4;
    }
    arch->hwcap = edx;

#define F(reg, bit, name)                                                      \
    if ((reg) & (1U << (bit)))                                                 \
        set_feature(arch, X86_FEATURE_##name);

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

#undef F

    if (max_ext_func >= 0x80000004) {
        uint32_t* p = (uint32_t*)arch->model_name;
        for (int i = 0; i < 3; ++i, p += 4)
            cpuid(0x80000002 + i, p, p + 1, p + 2, p + 3);
    }
    if (max_ext_func >= 0x80000007) {
        cpuid(0x80000007, &eax, &ebx, &ecx, &edx);
        if (edx & (1 << 8)) {
            set_feature(arch, X86_FEATURE_CONSTANT_TSC);
            set_feature(arch, X86_FEATURE_NONSTOP_TSC);
        }
    }
    if (max_ext_func >= 0x80000008) {
        cpuid(0x80000008, &eax, &ebx, &ecx, &edx);
        arch->phys_addr_bits = eax & 0xff;
        arch->virt_addr_bits = (eax >> 8) & 0xff;
    }
    if (arch->phys_addr_bits == 0)
        arch->phys_addr_bits = cpu_has_feature(cpu, X86_FEATURE_PAE) ? 36 : 32;
    if (arch->virt_addr_bits == 0) {
#ifdef ARCH_I386
        arch->virt_addr_bits = 32;
#endif
#ifdef ARCH_X86_64
        arch->virt_addr_bits = cpu_has_feature(cpu, X86_FEATURE_LA57) ? 57 : 48;
#endif
    }
}

struct fpu_state initial_fpu_state;

static void enable_features(struct cpu* cpu) {
    if (cpu_has_feature(cpu, X86_FEATURE_XMM)) {
        ASSERT(cpu_has_feature(cpu, X86_FEATURE_FXSR));

        unsigned long cr0 = read_cr0();
        cr0 &= ~X86_CR0_EM;
        cr0 |= X86_CR0_MP;
        write_cr0(cr0);

        write_cr4(read_cr4() | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT);
    }

    if (cpu == cpu_get_bsp()) {
        __asm__ volatile("fninit");
        // NOLINTBEGIN(bugprone-branch-clone)
        if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
            __asm__ volatile("fxsave %0" : "=m"(initial_fpu_state));
        else
            __asm__ volatile("fnsave %0" : "=m"(initial_fpu_state));
        // NOLINTEND(bugprone-branch-clone)
    }

    if (cpu_has_feature(cpu, X86_FEATURE_PGE))
        write_cr4(read_cr4() | X86_CR4_PGE);

    if (cpu_has_feature(cpu, X86_FEATURE_PAT)) {
        uint64_t pat = rdmsr(MSR_IA32_CR_PAT);
        pat &= ~((uint64_t)0x7 << 32); // Clear PAT4
        pat |= (uint64_t)1 << 32;      // Set write-combining
        wrmsr(MSR_IA32_CR_PAT, pat);
    }

    if (cpu_has_feature(cpu, X86_FEATURE_NX))
        wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_NX);

    if (cpu_has_feature(cpu, X86_FEATURE_SMEP))
        write_cr4(read_cr4() | X86_CR4_SMEP);
    if (cpu_has_feature(cpu, X86_FEATURE_SMAP))
        write_cr4(read_cr4() | X86_CR4_SMAP);
    if (cpu_has_feature(cpu, X86_FEATURE_UMIP))
        write_cr4(read_cr4() | X86_CR4_UMIP);
}

void cpu_init_features(void) {
    struct cpu* cpu = cpu_get_current();
    detect_features(cpu);
    enable_features(cpu);
}

void cpu_init_smp(void) {
    const struct acpi* acpi = acpi_get();
    ASSERT(acpi);
    for (const struct local_apic** p = acpi->local_apics; *p; ++p) {
        if (!((*p)->flags & ACPI_LOCAL_APIC_ENABLED))
            continue;

        uint8_t apic_id = (*p)->apic_id;
        if (apic_id == cpu_get_bsp()->arch.apic_id)
            continue;

        for (size_t i = 0; i < num_cpus; ++i)
            ASSERT(cpus[i]->arch.apic_id != apic_id);

        struct cpu* cpu = cpu_add();
        ASSERT(cpu);
        cpu->arch.apic_id = apic_id;
    }
}

void arch_cpu_broadcast_ipi(void) { lapic_broadcast_ipi(); }

void arch_cpu_unicast_ipi(struct cpu* dest) {
    lapic_unicast_ipi(dest->arch.apic_id);
}

NODISCARD
static int print_flag(struct vec* vec, const struct cpu* cpu, int feature,
                      const char* name) {
    if (!name[0]) {
        // Skip empty names
        return 0;
    }
    if (!cpu_has_feature(cpu, feature))
        return 0;
    return vec_printf(vec, "%s ", name);
}

int proc_print_cpuinfo(struct file* file, struct vec* vec) {
    (void)file;

    for (size_t i = 0; i < num_cpus; ++i) {
        struct cpu* cpu = cpus[i];
        struct arch_cpu* arch = &cpu->arch;
        int ret = vec_printf(vec,
                             "processor       : %zu\n"
                             "vendor_id       : %s\n"
                             "cpu family      : %u\n"
                             "model           : %u\n"
                             "model name      : %s\n",
                             i, arch->vendor_id, arch->family, arch->model,
                             arch->model_name);
        if (IS_ERR(ret))
            return ret;

        if (arch->stepping) {
            ret = vec_printf(vec, "stepping        : %u\n", arch->stepping);
            if (IS_ERR(ret))
                return ret;
        }

        const char* fpu = cpu_has_feature(cpu, X86_FEATURE_FPU) ? "yes" : "no";
        ret = vec_printf(vec,
                         "apicid          : %u\n"
                         "fpu             : %s\n"
                         "fpu_exception   : %s\n"
                         "wp              : yes\n"
                         "flags           : ",
                         cpu->arch.apic_id, fpu, fpu);
        if (IS_ERR(ret))
            return ret;

#define F(variant, name)                                                       \
    ret = print_flag(vec, cpu, X86_FEATURE_##variant, #name);                  \
    if (IS_ERR(ret))                                                           \
        return ret;
        ENUMERATE_X86_FEATURES(F)
#undef F

        ret = vec_printf(
            vec, "\naddress sizes   : %u bits physical, %u bits virtual\n\n",
            arch->phys_addr_bits, arch->virt_addr_bits);
        if (IS_ERR(ret))
            return ret;
    }

    return 0;
}
