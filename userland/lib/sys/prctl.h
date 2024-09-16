#pragma once

#include <kernel/api/sys/prctl.h>

int prctl(int op, ...
		  /* unsigned long arg2, unsigned long arg3,
		  unsigned long arg4, unsigned long arg5 */);
