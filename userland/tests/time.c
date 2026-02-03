#include <common/macros.h>
#include <errno.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

int main(void) {
    ASSERT_OK(settimeofday(NULL, NULL));
    ASSERT_OK(gettimeofday(NULL, NULL));

    struct timezone original_tz;
    ASSERT_OK(gettimeofday(NULL, &original_tz));

    struct timezone tz;
    tz.tz_minuteswest = 60 * 16;
    tz.tz_dsttime = original_tz.tz_dsttime;
    errno = 0;
    ASSERT_ERR(settimeofday(NULL, &tz));
    ASSERT(errno == EINVAL);

    tz.tz_minuteswest = 60;
    tz.tz_dsttime = 1;
    ASSERT_OK(settimeofday(NULL, &tz));

    tz.tz_minuteswest = -1;
    tz.tz_dsttime = -1;
    ASSERT_OK(gettimeofday(NULL, &tz));
    ASSERT(tz.tz_minuteswest == 60);
    ASSERT(tz.tz_dsttime == 1);

    ASSERT_OK(settimeofday(NULL, &original_tz));

    struct timespec original_ts;
    ASSERT_OK(clock_gettime(CLOCK_REALTIME, &original_ts));

    int64_t new_sec =
        MAX((int64_t)original_ts.tv_sec, (int64_t)UINT32_MAX) + 1000;
    struct timespec new_ts = {
        .tv_sec = new_sec,
        .tv_nsec = original_ts.tv_nsec,
    };
    ASSERT_OK(clock_settime(CLOCK_REALTIME, &new_ts));

    struct timespec ts;
    ASSERT_OK(clock_gettime(CLOCK_REALTIME, &ts));

    // Tolerate backward time adjustments
    ASSERT((int64_t)ts.tv_sec >= new_sec - 500);

    ASSERT_OK(clock_settime(CLOCK_REALTIME, &original_ts));

    return EXIT_SUCCESS;
}
