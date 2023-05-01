#pragma once

#include "api/sys/types.h"
#include "forward.h"

#define CLK_TCK 250

void timespec_add(struct timespec*, const struct timespec*);
void timespec_saturating_sub(struct timespec*, const struct timespec*);
int timespec_compare(const struct timespec*, const struct timespec*);

time_t rtc_now(void);

void time_init(void);
void time_tick(void);
void time_now(struct timespec*);
