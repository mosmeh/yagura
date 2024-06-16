#pragma once

typedef struct multiboot_info multiboot_info_t;

void drivers_init(const multiboot_info_t*);
