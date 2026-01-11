#pragma once

#define X86_EFLAGS_CF_BIT 0 /* Carry Flag */
#define X86_EFLAGS_CF (1U << X86_EFLAGS_CF_BIT)
#define X86_EFLAGS_FIXED_BIT 1 /* Bit 1 - always on */
#define X86_EFLAGS_FIXED (1U << X86_EFLAGS_FIXED_BIT)
#define X86_EFLAGS_PF_BIT 2 /* Parity Flag */
#define X86_EFLAGS_PF (1U << X86_EFLAGS_PF_BIT)
#define X86_EFLAGS_AF_BIT 4 /* Auxiliary carry Flag */
#define X86_EFLAGS_AF (1U << X86_EFLAGS_AF_BIT)
#define X86_EFLAGS_ZF_BIT 6 /* Zero Flag */
#define X86_EFLAGS_ZF (1U << X86_EFLAGS_ZF_BIT)
#define X86_EFLAGS_SF_BIT 7 /* Sign Flag */
#define X86_EFLAGS_SF (1U << X86_EFLAGS_SF_BIT)
#define X86_EFLAGS_TF_BIT 8 /* Trap Flag */
#define X86_EFLAGS_TF (1U << X86_EFLAGS_TF_BIT)
#define X86_EFLAGS_IF_BIT 9 /* Interrupt Flag */
#define X86_EFLAGS_IF (1U << X86_EFLAGS_IF_BIT)
#define X86_EFLAGS_DF_BIT 10 /* Direction Flag */
#define X86_EFLAGS_DF (1U << X86_EFLAGS_DF_BIT)
#define X86_EFLAGS_OF_BIT 11 /* Overflow Flag */
#define X86_EFLAGS_OF (1U << X86_EFLAGS_OF_BIT)
#define X86_EFLAGS_IOPL_BIT 12 /* I/O Privilege Level (2 bits) */
#define X86_EFLAGS_IOPL (3 << X86_EFLAGS_IOPL_BIT)
#define X86_EFLAGS_NT_BIT 14 /* Nested Task */
#define X86_EFLAGS_NT (1U << X86_EFLAGS_NT_BIT)
#define X86_EFLAGS_RF_BIT 16 /* Resume Flag */
#define X86_EFLAGS_RF (1U << X86_EFLAGS_RF_BIT)
#define X86_EFLAGS_VM_BIT 17 /* Virtual Mode */
#define X86_EFLAGS_VM (1U << X86_EFLAGS_VM_BIT)
#define X86_EFLAGS_AC_BIT 18 /* Alignment Check/Access Control */
#define X86_EFLAGS_AC (1U << X86_EFLAGS_AC_BIT)
#define X86_EFLAGS_VIF_BIT 19 /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIF (1U << X86_EFLAGS_VIF_BIT)
#define X86_EFLAGS_VIP_BIT 20 /* Virtual Interrupt Pending */
#define X86_EFLAGS_VIP (1U << X86_EFLAGS_VIP_BIT)
#define X86_EFLAGS_ID_BIT 21 /* CPUID detection */
#define X86_EFLAGS_ID (1U << X86_EFLAGS_ID_BIT)

#define X86_CR0_PE_BIT 0 /* Protection Enable */
#define X86_CR0_PE (1U << X86_CR0_PE_BIT)
#define X86_CR0_MP_BIT 1 /* Monitor Coprocessor */
#define X86_CR0_MP (1U << X86_CR0_MP_BIT)
#define X86_CR0_EM_BIT 2 /* Emulation */
#define X86_CR0_EM (1U << X86_CR0_EM_BIT)
#define X86_CR0_TS_BIT 3 /* Task Switched */
#define X86_CR0_TS (1U << X86_CR0_TS_BIT)
#define X86_CR0_ET_BIT 4 /* Extension Type */
#define X86_CR0_ET (1U << X86_CR0_ET_BIT)
#define X86_CR0_NE_BIT 5 /* Numeric Error */
#define X86_CR0_NE (1U << X86_CR0_NE_BIT)
#define X86_CR0_WP_BIT 16 /* Write Protect */
#define X86_CR0_WP (1U << X86_CR0_WP_BIT)
#define X86_CR0_AM_BIT 18 /* Alignment Mask */
#define X86_CR0_AM (1U << X86_CR0_AM_BIT)
#define X86_CR0_NW_BIT 29 /* Not Write-through */
#define X86_CR0_NW (1U << X86_CR0_NW_BIT)
#define X86_CR0_CD_BIT 30 /* Cache Disable */
#define X86_CR0_CD (1U << X86_CR0_CD_BIT)
#define X86_CR0_PG_BIT 31 /* Paging */
#define X86_CR0_PG (1U << X86_CR0_PG_BIT)

#define X86_CR4_VME_BIT 0 /* enable vm86 extensions */
#define X86_CR4_VME (1U << X86_CR4_VME_BIT)
#define X86_CR4_PVI_BIT 1 /* virtual interrupts flag enable */
#define X86_CR4_PVI (1U << X86_CR4_PVI_BIT)
#define X86_CR4_TSD_BIT 2 /* disable time stamp at ipl 3 */
#define X86_CR4_TSD (1U << X86_CR4_TSD_BIT)
#define X86_CR4_DE_BIT 3 /* enable debugging extensions */
#define X86_CR4_DE (1U << X86_CR4_DE_BIT)
#define X86_CR4_PSE_BIT 4 /* enable page size extensions */
#define X86_CR4_PSE (1U << X86_CR4_PSE_BIT)
#define X86_CR4_PAE_BIT 5 /* enable physical address extensions */
#define X86_CR4_PAE (1U << X86_CR4_PAE_BIT)
#define X86_CR4_MCE_BIT 6 /* Machine check enable */
#define X86_CR4_MCE (1U << X86_CR4_MCE_BIT)
#define X86_CR4_PGE_BIT 7 /* enable global pages */
#define X86_CR4_PGE (1U << X86_CR4_PGE_BIT)
#define X86_CR4_PCE_BIT 8 /* enable performance counters at ipl 3 */
#define X86_CR4_PCE (1U << X86_CR4_PCE_BIT)
#define X86_CR4_OSFXSR_BIT 9 /* enable fast FPU save and restore */
#define X86_CR4_OSFXSR (1U << X86_CR4_OSFXSR_BIT)
#define X86_CR4_OSXMMEXCPT_BIT 10 /* enable unmasked SSE exceptions */
#define X86_CR4_OSXMMEXCPT (1U << X86_CR4_OSXMMEXCPT_BIT)
#define X86_CR4_UMIP_BIT 11 /* enable UMIP support */
#define X86_CR4_UMIP (1U << X86_CR4_UMIP_BIT)
#define X86_CR4_LA57_BIT 12 /* enable 5-level page tables */
#define X86_CR4_LA57 (1U << X86_CR4_LA57_BIT)
#define X86_CR4_VMXE_BIT 13 /* enable VMX virtualization */
#define X86_CR4_VMXE (1U << X86_CR4_VMXE_BIT)
#define X86_CR4_SMXE_BIT 14 /* enable safer mode (TXT) */
#define X86_CR4_SMXE (1U << X86_CR4_SMXE_BIT)
#define X86_CR4_FSGSBASE_BIT 16 /* enable RDWRFSGS support */
#define X86_CR4_FSGSBASE (1U << X86_CR4_FSGSBASE_BIT)
#define X86_CR4_PCIDE_BIT 17 /* enable PCID support */
#define X86_CR4_PCIDE (1U << X86_CR4_PCIDE_BIT)
#define X86_CR4_OSXSAVE_BIT 18 /* enable xsave and xrestore */
#define X86_CR4_OSXSAVE (1U << X86_CR4_OSXSAVE_BIT)
#define X86_CR4_SMEP_BIT 20 /* enable SMEP support */
#define X86_CR4_SMEP (1U << X86_CR4_SMEP_BIT)
#define X86_CR4_SMAP_BIT 21 /* enable SMAP support */
#define X86_CR4_SMAP (1U << X86_CR4_SMAP_BIT)
#define X86_CR4_PKE_BIT 22 /* enable Protection Keys support */
#define X86_CR4_PKE (1U << X86_CR4_PKE_BIT)
#define X86_CR4_CET_BIT 23 /* enable Control-flow Enforcement Technology */
#define X86_CR4_CET (1U << X86_CR4_CET_BIT)
#define X86_CR4_LAM_SUP_BIT 28 /* LAM for supervisor pointers */
#define X86_CR4_LAM_SUP (1U << X86_CR4_LAM_SUP_BIT)
