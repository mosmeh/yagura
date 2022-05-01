#include "math.h"

double sqrt(double x) {
    double res;
    __asm__("fsqrt" : "=t"(res) : "0"(x));
    return res;
}

double log2(double x) {
    double ret;
    __asm__("fld1\n"
            "fxch %%st(1)\n"
            "fyl2x"
            : "=t"(ret)
            : "0"(x));
    return ret;
}
