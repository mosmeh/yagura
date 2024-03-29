#include "api/time.h"
#include "asm_wrapper.h"
#include "interrupts.h"
#include "panic.h"
#include "time.h"
#include <common/calendar.h>

void timespec_add(struct timespec* this, const struct timespec* other) {
    this->tv_sec += other->tv_sec;
    this->tv_nsec += other->tv_nsec;
    if (this->tv_nsec >= 1000000000) {
        ++this->tv_sec;
        this->tv_nsec -= 1000000000;
    }
}

void timespec_saturating_sub(struct timespec* this,
                             const struct timespec* other) {
    this->tv_sec -= other->tv_sec;
    this->tv_nsec -= other->tv_nsec;
    if (this->tv_nsec < 0) {
        --this->tv_sec;
        this->tv_nsec += 1000000000;
    }
    if (this->tv_sec < 0)
        this->tv_sec = this->tv_nsec = 0;
}

int timespec_compare(const struct timespec* a, const struct timespec* b) {
    if (a->tv_sec > b->tv_sec)
        return 1;
    if (a->tv_sec < b->tv_sec)
        return -1;
    if (a->tv_nsec > b->tv_nsec)
        return 1;
    if (a->tv_nsec < b->tv_nsec)
        return -1;
    return 0;
}

static uint8_t cmos_read(uint8_t idx) {
    out8(0x70, idx);
    return in8(0x71);
}

static uint8_t bcd_to_bin(uint8_t bcd) {
    return (bcd & 0xf) + ((bcd >> 4) * 10);
}

static unsigned days_since_epoch(unsigned year, unsigned month, unsigned day) {
    ASSERT(year >= 1970);
    unsigned days = day_of_year(year, month, day);
    for (unsigned y = 1970; y < year; ++y)
        days += days_in_year(y);
    return days;
}

time_t rtc_now(void) {
    int timeout = 100;
    bool update_finished = false;
    while (--timeout >= 0) {
        if (!(cmos_read(0x0a) & 0x80)) {
            update_finished = true;
            break;
        }
        delay(1000);
    }

    unsigned year = 1970;
    unsigned month = 1;
    unsigned day = 1;
    unsigned hour = 0;
    unsigned minute = 0;
    unsigned second = 0;

    if (update_finished) {
        uint8_t status = cmos_read(0xb);
        second = cmos_read(0x0);
        minute = cmos_read(0x2);
        hour = cmos_read(0x4);
        day = cmos_read(0x7);
        month = cmos_read(0x8);
        year = cmos_read(0x9);

        if (!(status & 0x4)) {
            second = bcd_to_bin(second);
            minute = bcd_to_bin(minute);
            hour = bcd_to_bin(hour & 0x7f);
            day = bcd_to_bin(day);
            month = bcd_to_bin(month);
            year = bcd_to_bin(year);
        }
        if (!(status & 0x2)) {
            hour %= 12;
            if (hour & 0x80)
                hour += 12;
        }

        year += 2000;
    }

    time_t days = days_since_epoch(year, month, day);
    time_t hours = days * 24 + hour;
    time_t minutes = hours * 60 + minute;
    return minutes * 60 + second;
}

static struct timespec now;

void time_init(void) {
    now.tv_sec = rtc_now();
    now.tv_nsec = 0;
}

void time_tick(void) {
    static const long nanos = 1000000000;

    bool int_flag = push_cli();

    now.tv_nsec += nanos / CLK_TCK;
    if (now.tv_nsec >= nanos) {
        ++now.tv_sec;
        now.tv_nsec -= nanos;
    }

    pop_cli(int_flag);
}

void time_now(struct timespec* tp) {
    bool int_flag = push_cli();
    *tp = now;
    pop_cli(int_flag);
}
