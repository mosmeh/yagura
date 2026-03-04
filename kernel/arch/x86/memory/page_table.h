#pragma once

// Page is mapped
#define PTE_PRESENT 0x1

// Page may be written
#define PTE_WRITE 0x2

// Page may be accessed from userland
#define PTE_USER 0x4

// PAT, PCD, and PWT bits index into Page Attribute Table
#define PTE_PWT 0x8
#define PTE_PCD 0x10
#define PTE_PAT 0x80

// Page is global (TLB entry is not invalidated on context switch)
#define PTE_GLOBAL 0x100

// Disable execution of code on this page
#define PTE_NX 0x8000000000000000
