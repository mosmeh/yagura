#pragma once

#include "forward.h"
#include <stdatomic.h>

#define CLK_TCK 250

extern atomic_uint uptime;

void timespec_add(struct timespec*, const struct timespec*);
void timespec_saturating_sub(struct timespec*, const struct timespec*);
int timespec_compare(const struct timespec*, const struct timespec*);

void time_init(void);
void time_now(struct timespec*);
