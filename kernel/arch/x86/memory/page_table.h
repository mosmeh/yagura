#pragma once

// Page is mapped
#define PTE_PRESENT 0x1

// Page may be written
#define PTE_WRITE 0x2

// Page may be accessed from userland
#define PTE_USER 0x4

// Page Attribute Table bit
// Used to enable write-combining caching.
#define PTE_PAT 0x80

// Page is global (not flushed from TLB on context switch)
#define PTE_GLOBAL 0x100

// Disable execution of code on this page
#define PTE_NX 0x8000000000000000
