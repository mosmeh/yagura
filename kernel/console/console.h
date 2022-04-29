#pragma once

#include <kernel/api/hid.h>
#include <stddef.h>

void fb_console_init(void);
void fb_console_on_key(const key_event*);
struct file* fb_console_device_create(void);

void system_console_init(void);
struct file* system_console_device_create(void);
