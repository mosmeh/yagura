#include "console.h"
#include "private.h"
#include "screen/screen.h"
#include <kernel/panic.h>

void console_init(void) {
    serial_console_init();

    struct screen* screen = screen_init();
    if (IS_OK(screen))
        virtual_console_init(screen);

    system_console_init();
}
