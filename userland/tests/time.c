#include <errno.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/time.h>

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

    return EXIT_SUCCESS;
}
