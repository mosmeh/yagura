#include <common/calendar.h>
#include <kernel/api/time.h>
#include <kernel/arch/io.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>

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

static time_t rtc_now(void) {
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

        kprintf("rtc: year=%u month=%u day=%u hour=%u minute=%u second=%u\n",
                year, month, day, hour, minute, second);
    } else {
        kprint("rtc: update did not finish within timeout. Falling back to "
               "UNIX epoch\n");
    }

    time_t days = days_since_epoch(year, month, day);
    time_t hours = days * 24 + hour;
    time_t minutes = hours * 60 + minute;
    return minutes * 60 + second;
}

void arch_time(struct timespec* ts) {
    *ts = (struct timespec){
        .tv_sec = rtc_now(),
    };
}
