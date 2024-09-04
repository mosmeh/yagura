#include "errno.h"
#include "stdlib.h"
#include "unistd.h"
#include <elf.h>
#include <extra.h>

static uint32_t auxv[32];

unsigned long getauxval(unsigned long type) {
    if (type >= ARRAY_SIZE(auxv)) {
        errno = ENOENT;
        return 0;
    }
    return auxv[type];
}

int main(int argc, char* const argv[], char* const envp[]);

void __start(unsigned long* args) {
    int argc = args[0];
    char** argv = (char**)(args + 1);
    environ = argv + argc + 1;

    char** p = environ;
    while (*p++)
        ;
    for (Elf32_auxv_t* aux = (Elf32_auxv_t*)p; aux->a_type != AT_NULL; ++aux) {
        if (aux->a_type < ARRAY_SIZE(auxv))
            auxv[aux->a_type] = aux->a_un.a_val;
    }

    exit(main(argc, argv, environ));
}
