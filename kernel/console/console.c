#include "console.h"

void serial_console_init(void);
void fb_console_init(void);
void system_console_init(void);

void console_init(void) {
    serial_console_init();
    fb_console_init();
    system_console_init();
}
