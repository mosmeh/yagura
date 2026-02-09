#include <common/stdbool.h>
#include <errno.h>
#include <panic.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

static int global_var = 42;
static _Thread_local int thread_local_var = 84;

static void* thread1(void* arg) {
    ASSERT((uintptr_t)arg == 0x1234);
    ASSERT(pthread_join(pthread_self(), NULL) == EDEADLK);
    global_var = 123;
    thread_local_var = 456;
    return (void*)0x5678;
}

static void* thread2(void* arg) {
    ASSERT((uintptr_t)arg == 0x4242);
    pthread_exit((void*)0xa5a5);
    UNREACHABLE();
}

static _Atomic(bool) should_exit = false;

static void* thread3(void* arg) {
    (void)arg;
    while (!should_exit)
        usleep(1000);
    return (void*)0xdeadbeef;
}

static _Atomic(bool) received_signal = false;

static void signal_handler(int signum) {
    ASSERT(signum == SIGUSR1);
    received_signal = true;
}

static void* thread4(void* arg) {
    (void)arg;
    while (!received_signal) {
        errno = 0;
        if (usleep(1000) < 0) {
            ASSERT(errno == EINTR);
            break;
        }
    }
    return NULL;
}

int main(void) {
    pthread_t thread;
    void* retval;

    ASSERT(pthread_create(&thread, NULL, thread1, (void*)0x1234) == 0);
    ASSERT(pthread_join(thread, &retval) == 0);
    ASSERT(pthread_join(thread, NULL) == ESRCH);
    ASSERT(retval == (void*)0x5678);
    ASSERT(global_var == 123);
    ASSERT(thread_local_var == 84);

    ASSERT(pthread_create(&thread, NULL, thread2, (void*)0x4242) == 0);
    ASSERT(pthread_join(thread, &retval) == 0);
    ASSERT(retval == (void*)0xa5a5);

    pthread_attr_t attr;
    ASSERT(pthread_attr_init(&attr) == 0);
    ASSERT(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0);
    ASSERT(pthread_create(&thread, &attr, thread3, NULL) == 0);
    ASSERT(pthread_attr_destroy(&attr) == 0);
    ASSERT(pthread_join(thread, NULL) == EINVAL);
    should_exit = true;

    ASSERT(signal(SIGUSR1, signal_handler) != SIG_ERR);

    ASSERT(pthread_create(&thread, NULL, thread4, NULL) == 0);
    ASSERT(pthread_kill(thread, SIGUSR1) == 0);
    ASSERT(pthread_join(thread, NULL) == 0);
    ASSERT(received_signal);

    return EXIT_SUCCESS;
}
