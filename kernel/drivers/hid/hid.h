#pragma once

#include <common/stdbool.h>

struct keyboard_events {
    void (*raw)(unsigned char scancode);
    void (*key)(unsigned char keycode, bool down);
};

void keyboard_set_event_handlers(const struct keyboard_events*);
