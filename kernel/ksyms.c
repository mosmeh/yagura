#include "memory/memory.h"
#include "panic.h"
#include "system.h"
#include <stdint.h>

extern char ksyms_start[];
extern char ksyms_end[];

static size_t num_symbols;
static struct symbol* symbols;
static uintptr_t lowest_addr;

static unsigned int parse_hex_digit(char c) {
    if ('0' <= c && c <= '9')
        return c - '0';
    ASSERT('a' <= c && c <= 'f');
    return c - 'a' + 10;
}

void ksyms_init(void) {
    // Parse the output of `nm -n`
    // e.g. c0110580 T start

    size_t n = 0;
    for (const char* p = ksyms_start; p < ksyms_end; ++p)
        n += *p == '\n';
    symbols = kmalloc(n * sizeof(struct symbol));

    struct symbol* symbol = symbols;
    for (char* p = ksyms_start; p < ksyms_end; ++p, ++symbol) {
        uintptr_t addr = 0;
        for (; *p != ' '; ++p)
            addr = addr * 16 + parse_hex_digit(*p);
        if (symbol == symbols)
            lowest_addr = addr;
        symbol->addr = addr;

        while (*p == ' ')
            ++p;

        symbol->type = *p++;

        while (*p == ' ')
            ++p;

        symbol->name = p;
        while (*p != '\n')
            ++p;
        *p = 0; // Replace '\n' with '\0'
    }

    num_symbols = n;
}

const struct symbol* ksyms_lookup(uintptr_t addr) {
    if (num_symbols == 0 || addr < lowest_addr)
        return NULL;
    for (size_t i = 0; i < num_symbols - 1; ++i) {
        if (addr < symbols[i + 1].addr)
            return symbols + i;
    }
    return NULL;
}

const struct symbol* ksyms_next(const struct symbol* symbol) {
    if (num_symbols == 0)
        return NULL;
    if (symbol == NULL || symbol < symbols)
        return symbols;
    if (symbol >= symbols + num_symbols - 1)
        return NULL;
    return symbol + 1;
}
