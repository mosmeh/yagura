#pragma once

#include <kernel/api/sys/ioctl.h>

int ioctl(int fd, unsigned cmd, ...);
