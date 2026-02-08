#include <errno.h>
#include <panic.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

static void* thread1(void* arg) {
    ASSERT((uintptr_t)arg == 0x1234);
    return (void*)0x5678;
}

static void* thread2(void* arg) {
    ASSERT((uintptr_t)arg == 0x4242);
    pthread_exit((void*)0xa5a5);
    UNREACHABLE();
}

static void* thread3(void* arg) {
    (void)arg;
    for (;;)
        sleep(1);
    UNREACHABLE();
}

int main(void) {
    pthread_t thread;
    void* retval;

    ASSERT(pthread_create(&thread, NULL, thread1, (void*)0x1234) == 0);
    ASSERT(pthread_join(thread, &retval) == 0);
    ASSERT(retval == (void*)0x5678);

    ASSERT(pthread_create(&thread, NULL, thread2, (void*)0x4242) == 0);
    ASSERT(pthread_join(thread, &retval) == 0);
    ASSERT(retval == (void*)0xa5a5);

    ASSERT(pthread_create(&thread, NULL, thread1, (void*)0x1234) == 0);
    ASSERT(pthread_detach(thread) == 0);
    ASSERT(pthread_join(thread, NULL) == EINVAL);

    ASSERT(pthread_create(&thread, NULL, thread3, NULL) == 0);
    ASSERT(pthread_kill(thread, SIGTERM) == 0);

    return EXIT_SUCCESS;
}
