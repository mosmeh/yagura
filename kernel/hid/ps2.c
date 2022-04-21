#include "hid.h"

void ps2_keyboard_init(void);
void ps2_mouse_init(void);

void ps2_init(void) {
    ps2_write(PS2_COMMAND, PS2_DISABLE_PORT1);
    ps2_write(PS2_COMMAND, PS2_DISABLE_PORT2);

    ps2_write(PS2_COMMAND, PS2_READ_CONFIG);
    uint8_t config = ps2_read(PS2_DATA);
    config |= PS2_INTERRUPT_PORT1 | PS2_INTERRUPT_PORT2;
    ps2_write(PS2_COMMAND, PS2_WRITE_CONFIG);
    ps2_write(PS2_DATA, config);

    ps2_keyboard_init();
    ps2_mouse_init();
}
