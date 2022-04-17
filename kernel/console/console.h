#pragma once

#include <kernel/api/hid.h>

void tty_init(void);
void tty_on_key(const key_event*);
struct file* tty_device_create(void);
