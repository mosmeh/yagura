#include "hid.h"

void ps2_keyboard_init(void);
void ps2_mouse_init(void);

void ps2_init(void) {
    ps2_write(PS2_COMMAND, PS2_DISABLE_PORT1);
    ps2_write(PS2_COMMAND, PS2_DISABLE_PORT2);

    ps2_write(PS2_COMMAND, 0x20); // read config
    uint8_t config = ps2_read(PS2_DATA);
    ps2_write(PS2_COMMAND, 0x60);    // write config
    ps2_write(PS2_DATA, config | 3); // enable IRQ1 and IRQ12

    ps2_write(PS2_COMMAND, PS2_ENABLE_PORT1);
    ps2_write(PS2_COMMAND, PS2_ENABLE_PORT2);

    ps2_keyboard_init();
    ps2_mouse_init();
}
