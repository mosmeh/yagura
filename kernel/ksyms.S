    .data
    .globl ksyms_start, ksyms_end
ksyms_start:
#ifdef KSYMS
    .incbin KSYMS
#endif
ksyms_end:
