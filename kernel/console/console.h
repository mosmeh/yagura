#pragma once

#include <kernel/api/hid.h>
#include <stddef.h>

void tty_init(void);
void tty_on_key(const key_event*);
struct file* tty_device_create(void);

void console_init(void);
struct file* console_device_create(void);
