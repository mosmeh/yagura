#pragma once

#include "gdt.h"
#include <common/extra.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ENUMERATE_X86_FEATURES(F)                                              \
    F(FPU, fpu)         /* Onboard FPU */                                      \
    F(VME, vme)         /* Virtual Mode Extensions */                          \
    F(DE, de)           /* Debugging Extensions */                             \
    F(PSE, pse)         /* Page Size Extensions */                             \
    F(TSC, tsc)         /* Time Stamp Counter */                               \
    F(MSR, msr)         /* Model-Specific Registers */                         \
    F(PAE, pae)         /* Physical Address Extensions */                      \
    F(MCE, mce)         /* Machine Check Exception */                          \
    F(CX8, cx8)         /* CMPXCHG8 instruction */                             \
    F(APIC, apic)       /* Onboard APIC */                                     \
    F(SEP, sep)         /* SYSENTER/SYSEXIT */                                 \
    F(MTRR, mtrr)       /* Memory Type Range Registers */                      \
    F(PGE, pge)         /* Page Global Enable */                               \
    F(MCA, mca)         /* Machine Check Architecture */                       \
    F(CMOV, cmov)       /* CMOV instructions (plus FCMOVcc, FCOMI with FPU) */ \
    F(PAT, pat)         /* Page Attribute Table */                             \
    F(PSE36, pse36)     /* 36-bit PSEs */                                      \
    F(PN, pn)           /* Processor serial number */                          \
    F(CLFLUSH, clflush) /* CLFLUSH instruction */                              \
    F(DS, dts)          /* Debug Store */                                      \
    F(ACPI, acpi)       /* ACPI via MSR */                                     \
    F(MMX, mmx)         /* Multimedia Extensions */                            \
    F(FXSR, fxsr)       /* FXSAVE/FXRSTOR, CR4.OSFXSR */                       \
    F(XMM, sse)                                                                \
    F(XMM2, sse2)                                                              \
    F(SELFSNOOP, ss)              /* CPU self snoop */                         \
    F(HT, ht)                     /* Hyper-Threading */                        \
    F(ACC, tm)                    /* Automatic clock control */                \
    F(IA64, ia64)                 /* IA-64 processor */                        \
    F(PBE, pbe)                   /* Pending Break Enable */                   \
    F(SYSCALL, syscall)           /* SYSCALL/SYSRET */                         \
    F(MP, mp)                     /* MP Capable */                             \
    F(NX, nx)                     /* Execute Disable */                        \
    F(MMXEXT, mmxext)             /* AMD MMX extensions */                     \
    F(FXSR_OPT, fxsr_opt)         /* FXSAVE/FXRSTOR optimizations */           \
    F(GBPAGES, pdpe1gb)           /* GB pages */                               \
    F(RDTSCP, rdtscp)             /* RDTSCP */                                 \
    F(LM, lm)                     /* Long Mode (x86-64, 64-bit support) */     \
    F(3DNOWEXT, 3dnowext)         /* AMD 3DNow extensions */                   \
    F(3DNOW, 3dnow)               /* 3DNow */                                  \
    F(CONSTANT_TSC, constant_tsc) /* TSC ticks at a constant rate */           \
    F(NONSTOP_TSC, nonstop_tsc)   /* TSC does not stop in C states */          \
    F(XMM3, pni)                  /* SSE-3 */                                  \
    F(PCLMULQDQ, pclmulqdq)       /* PCLMULQDQ instruction */                  \
    F(DTES64, dtes64)             /* 64-bit Debug Store */                     \
    F(MWAIT, monitor)             /* MONITOR/MWAIT support */                  \
    F(DSCPL, ds_cpl)              /* CPL-qualified (filtered) Debug Store */   \
    F(VMX, vmx)                   /* Hardware virtualization */                \
    F(SMX, smx)                   /* Safer Mode eXtensions */                  \
    F(EST, est)                   /* Enhanced SpeedStep */                     \
    F(TM2, tm2)                   /* Thermal Monitor 2 */                      \
    F(SSSE3, ssse3)               /* Supplemental SSE-3 */                     \
    F(CID, cid)                   /* Context ID */                             \
    F(SDBG, sdbg)                 /* Silicon Debug */                          \
    F(FMA, fma)                   /* Fused multiply-add */                     \
    F(CX16, cx16)                 /* CMPXCHG16B instruction */                 \
    F(XTPR, xtpr)                 /* Send Task Priority Messages */            \
    F(PDCM, pdcm)                 /* Perf/Debug Capabilities MSR */            \
    F(PCID, pcid)                 /* Process Context Identifiers */            \
    F(DCA, dca)                   /* Direct Cache Access */                    \
    F(XMM4_1, sse4_1)             /* SSE-4.1 */                                \
    F(XMM4_2, sse4_2)             /* SSE-4.2 */                                \
    F(X2APIC, x2apic)             /* X2APIC */                                 \
    F(MOVBE, movbe)               /* MOVBE instruction */                      \
    F(POPCNT, popcnt)             /* POPCNT instruction */                     \
    F(TSC_DEADLINE_TIMER, tsc_deadline_timer) /* TSC deadline timer */         \
    F(AES, aes)                               /* AES instructions */           \
    F(XSAVE, xsave)             /* XSAVE/XRSTOR/XSETBV/XGETBV instructions */  \
    F(OSXSAVE, )                /* XSAVE instruction enabled in the OS */      \
    F(AVX, avx)                 /* Advanced Vector Extensions */               \
    F(F16C, f16c)               /* 16-bit FP conversions */                    \
    F(RDRAND, rdrand)           /* RDRAND instruction */                       \
    F(HYPERVISOR, hypervisor)   /* Running on a hypervisor */                  \
    F(LAHF_LM, lahf_lm)         /* LAHF/SAHF in long mode */                   \
    F(CMP_LEGACY, cmp_legacy)   /* If yes HyperThreading not valid */          \
    F(SVM, svm)                 /* Secure Virtual Machine */                   \
    F(EXTAPIC, extapic)         /* Extended APIC space */                      \
    F(CR8_LEGACY, cr8_legacy)   /* CR8 in 32-bit mode */                       \
    F(ABM, abm)                 /* Advanced bit manipulation */                \
    F(SSE4A, sse4a)             /* SSE-4A */                                   \
    F(MISALIGNSSE, misalignsse) /* Misaligned SSE mode */                      \
    F(3DNOWPREFETCH, 3dnowprefetch) /* 3DNow prefetch instructions */          \
    F(OSVW, osvw)                   /* OS Visible Workaround */                \
    F(IBS, ibs)                     /* Instruction Based Sampling */           \
    F(XOP, xop)                     /* extended AVX instructions */            \
    F(SKINIT, skinit)               /* SKINIT/STGI instructions */             \
    F(WDT, wdt)                     /* Watchdog timer */                       \
    F(LWP, lwp)                     /* Light Weight Profiling */               \
    F(FMA4, fma4)                   /* 4 operands MAC instructions */          \
    F(TCE, tce)                     /* Translation Cache Extension */          \
    F(NODEID_MSR, nodeid_msr)       /* NodeId MSR */                           \
    F(TBM, tbm)                     /* Trailing Bit Manipulations */           \
    F(TOPOEXT, topoext)             /* Topology extensions CPUID leafs */      \
    F(PERFCTR_CORE, perfctr_core)   /* Core performance counter extensions */  \
    F(PERFCTR_NB, perfctr_nb)       /* NB performance counter extensions */    \
    F(BPEXT, bpext)                 /* Data breakpoint extension */            \
    F(PTSC, ptsc)                   /* Performance time-stamp counter */       \
    F(PERFCTR_LLC,                                                             \
      perfctr_llc)    /* Last Level Cache performance counter extensions */    \
    F(MWAITX, mwaitx) /* MWAIT extension (MONITORX/MWAITX instructions) */     \
    F(FSGSBASE,                                                                \
      fsgsbase) /* RDFSBASE, WRFSBASE, RDGSBASE, WRGSBASE instructions*/       \
    F(TSC_ADJUST, tsc_adjust) /* TSC adjustment MSR 0x3B */                    \
    F(SGX, sgx)               /* Software Guard Extensions */                  \
    F(BMI1, bmi1)             /* 1st group bit manipulation extensions */      \
    F(HLE, hle)               /* Hardware Lock Elision */                      \
    F(AVX2, avx2)             /* AVX2 instructions */                          \
    F(FDP_EXCPTN_ONLY, ) /* FPU data pointer updated only on x87 exceptions */ \
    F(SMEP, smep)        /* Supervisor Mode Execution Protection */            \
    F(BMI2, bmi2)        /* 2nd group bit manipulation extensions */           \
    F(ERMS, erms)        /* Enhanced REP MOVSB/STOSB instructions */           \
    F(INVPCID, invpcid)  /* Invalidate Processor Context ID */                 \
    F(RTM, rtm)          /* Restricted Transactional Memory */                 \
    F(CQM, cqm)          /* Cache QoS Monitoring */                            \
    F(ZERO_FCS_FDS, )    /*  Zero out FPU CS and FPU DS */                     \
    F(MPX, mpx)          /* Memory Protection Extension */                     \
    F(RDT_A, rdt_a)      /* Resource Director Technology Allocation */         \
    F(AVX512F, avx512f)  /* AVX-512 Foundation */                              \
    F(AVX512DQ, avx512dq) /* AVX-512 DQ (Double/Quad granular) Instructions */ \
    F(RDSEED, rdseed)     /* RDSEED instruction */                             \
    F(ADX, adx)           /* ADCX and ADOX instructions */                     \
    F(SMAP, smap)         /* Supervisor Mode Access Prevention */              \
    F(AVX512IFMA,                                                              \
      avx512ifma) /* AVX-512 Integer Fused Multiply-Add instructions */        \
    F(CLFLUSHOPT, clflushopt) /* CLFLUSHOPT instruction */                     \
    F(CLWB, clwb)             /* CLWB instruction */                           \
    F(INTEL_PT, intel_pt)     /* Intel Processor Trace */                      \
    F(AVX512PF, avx512pf)     /* AVX-512 Prefetch */                           \
    F(AVX512ER, avx512er)     /* AVX-512 Exponential and Reciprocal */         \
    F(AVX512CD, avx512cd)     /* AVX-512 Conflict Detection */                 \
    F(SHA_NI, sha_ni)         /* SHA1/SHA256 Instruction Extensions */         \
    F(AVX512BW, avx512bw) /* AVX-512 BW (Byte/Word granular) Instructions */   \
    F(AVX512VL, avx512vl) /* AVX-512 VL (128/256 Vector Length) Extensions */  \
    F(AVX512VBMI, avx512vbmi) /* AVX512 Vector Bit Manipulation instructions*/ \
    F(UMIP, umip)             /* User Mode Instruction Protection */           \
    F(PKU, pku)               /* Protection Keys for Userspace */              \
    F(OSPKE, ospke)           /* OS Protection Keys Enable */                  \
    F(WAITPKG, waitpkg)       /* UMONITOR/UMWAIT/TPAUSE Instructions */        \
    F(AVX512_VBMI2, avx512_vbmi2) /* Additional AVX512 Vector Bit Manipulation \
                                     Instructions */                           \
    F(SHSTK, )                    /* Shadow stack */                           \
    F(GFNI, gfni)                 /* Galois Field New Instructions */          \
    F(VAES, vaes)                 /* Vector AES */                             \
    F(VPCLMULQDQ, vpclmulqdq) /* Carry-Less Multiplication Double Quadword */  \
    F(AVX512_VNNI, avx512_vnni)     /* Vector Neural Network Instructions */   \
    F(AVX512_BITALG, avx512_bitalg) /* Support for VPOPCNT[B,W] and            \
                                       VPSHUF-BITQMB instructions */           \
    F(TME, tme)                     /* Intel Total Memory Encryption */        \
    F(AVX512_VPOPCNTDQ, avx512_vpopcntdq) /* POPCNT for vectors of DW/QW */    \
    F(LA57, la57)                         /* 5-level page tables */            \
    F(RDPID, rdpid)                       /* RDPID instruction */              \
    F(BUS_LOCK_DETECT, bus_lock_detect)   /* Bus Lock detect */                \
    F(CLDEMOTE, cldemote)                 /* CLDEMOTE instruction */           \
    F(MOVDIRI, movdiri)                   /* MOVDIRI instruction */            \
    F(MOVDIR64B, movdir64b)               /* MOVDIR64B instruction */          \
    F(ENQCMD, enqcmd) /* ENQCMD and ENQCMDS instructions */                    \
    F(SGX_LC, sgx_lc) /* Software Guard Extensions Launch Control */           \
    F(AVX512_4VNNIW, avx512_4vnniw) /* AVX-512 Neural Network Instructions */  \
    F(AVX512_4FMAPS,                                                           \
      avx512_4fmaps) /* AVX-512 Multiply Accumulation Single precision */      \
    F(FSRM, fsrm)    /* Fast Short Rep Mov */                                  \
    F(AVX512_VP2INTERSECT,                                                     \
      avx512_vp2intersect)      /* AVX-512 Intersect for D/Q */                \
    F(SRBDS_CTRL, )             /* SRBDS mitigation MSR available */           \
    F(MD_CLEAR, md_clear)       /* VERW clears CPU buffers */                  \
    F(RTM_ALWAYS_ABORT, )       /* RTM transaction always aborts */            \
    F(TSX_FORCE_ABORT, )        /* TSX_FORCE_ABORT */                          \
    F(SERIALIZE, serialize)     /* SERIALIZE instruction */                    \
    F(HYBRID_CPU, )             /* This part has CPUs of more than one type */ \
    F(TSXLDTRK, tsxldtrk)       /* TSX Suspend Load Address Tracking */        \
    F(PCONFIG, pconfig)         /* Intel PCONFIG */                            \
    F(ARCH_LBR, arch_lbr)       /* Intel ARCH LBR */                           \
    F(IBT, ibt)                 /* Indirect Branch Tracking */                 \
    F(AMX_BF16, amx_bf16)       /* AMX bf16 Support */                         \
    F(AVX512_FP16, avx512_fp16) /* AVX512 FP16 */                              \
    F(AMX_TILE, amx_tile)       /* AMX tile Support */                         \
    F(AMX_INT8, amx_int8)       /* AMX int8 Support */                         \
    F(SPEC_CTRL, )              /* Speculation Control (IBRS + IBPB) */        \
    F(INTEL_STIBP, )            /* Single Thread Indirect Branch Predictors */ \
    F(FLUSH_L1D, flush_l1d)     /* Flush L1D cache */                          \
    F(ARCH_CAPABILITIES,                                                       \
      arch_capabilities)   /* IA32_ARCH_CAPABILITIES MSR (Intel) */            \
    F(CORE_CAPABILITIES, ) /* IA32_CORE_CAPABILITIES MSR */                    \
    F(SPEC_CTRL_SSBD, )    /* Speculative Store Bypass Disable */

enum {
#define F(variant, name) X86_FEATURE_##variant,
    ENUMERATE_X86_FEATURES(F)
#undef F
        NUM_X86_FEATURES
};

struct cpu {
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    uint32_t features[NUM_X86_FEATURES / 32 + 1];
    uint8_t apic_id;
    uint8_t phys_addr_bits;
    uint8_t virt_addr_bits;
    // ebx, ecx, edx + '\0'
    char vendor_id[3 * sizeof(uint32_t) + 1];
    // 3 * (eax, ebx, ecx, edx) + '\0'
    char model_name[3 * 4 * sizeof(uint32_t) + 1];

    struct gdt_segment gdt[NUM_GDT_ENTRIES];
    struct tss tss;
    struct gdtr gdtr;

    struct task* current_task;
    struct task* idle_task;

    struct mpsc* msg_queue;
};

#define MAX_NUM_CPUS (UINT8_MAX + 1)

extern size_t num_cpus;
extern struct cpu* cpus[MAX_NUM_CPUS];

void cpu_init(void);
void cpu_init_smp(void);

uint8_t cpu_get_id(void);
struct cpu* cpu_get_bsp(void);
struct cpu* cpu_get_current(void);
bool cpu_has_feature(const struct cpu*, int feature);

void cpu_pause(void);

struct ipi_message {
    enum {
        IPI_MESSAGE_HALT,
        IPI_MESSAGE_FLUSH_TLB,
    } type;
    atomic_size_t ref_count;
    struct {
        uintptr_t virt_addr;
        size_t size;
    } flush_tlb;
};

void cpu_broadcast_message(struct ipi_message*);
void cpu_unicast_message(struct cpu*, struct ipi_message*);
struct ipi_message* cpu_alloc_message(void);
void cpu_free_message(struct ipi_message*);
void cpu_process_messages(void);
