#define STRINGIFY(s) _STRINGIFY(s)
#define _STRINGIFY(s) #s

.globl ksyms_start, ksyms_end
ksyms_start:
#ifdef KSYMS
.incbin STRINGIFY(KSYMS)
#endif
ksyms_end:
