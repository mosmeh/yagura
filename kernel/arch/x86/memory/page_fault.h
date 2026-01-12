#pragma once

#include <common/stdbool.h>

#define X86_PF_PROT 0x1
#define X86_PF_WRITE 0x2
#define X86_PF_USER 0x4
#define X86_PF_RSVD 0x8
#define X86_PF_INSTR 0x10

struct registers;

bool x86_handle_page_fault(struct registers*, void* addr);

bool safe_string_handle_page_fault(struct registers* regs,
                                   unsigned long error_code);
