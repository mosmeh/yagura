#include <panic.h>
#include <stdlib.h>
#include <sys/klog.h>

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_UNREAD 9
#define SYSLOG_ACTION_SIZE_BUFFER 10

int main(void) {
    ASSERT(klogctl(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0) > 0);

    int size = ASSERT_OK(klogctl(SYSLOG_ACTION_SIZE_UNREAD, NULL, 0));
    if (size > 0) {
        char* buf = ASSERT(malloc(size));
        ASSERT_OK(klogctl(SYSLOG_ACTION_READ_ALL, buf, size));
        free(buf);
    }

    return EXIT_SUCCESS;
}
