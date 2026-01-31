#include <common/stdbool.h>
#include <errno.h>
#include <panic.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static _Atomic(bool) sigusr1_received = false;
static _Atomic(bool) sigusr2_received = false;

static void handler1(int signum) {
    ASSERT(signum == SIGUSR1);
    sigusr1_received = true;
}

static void handler2(int signum) {
    ASSERT(signum == SIGUSR2);
    sigusr2_received = true;
}

int main(void) {
    errno = 0;
    ASSERT(signal(-1, handler1) == SIG_ERR);
    ASSERT(errno == EINVAL);

    ASSERT_OK(signal(SIGUSR1, handler1));
    ASSERT_OK(kill(getpid(), SIGUSR1));
    ASSERT(sigusr1_received);

    ASSERT_OK(sigaction(SIGUSR2, NULL, NULL));

    struct sigaction sa;
    ASSERT_OK(sigaction(SIGUSR2, NULL, &sa));
    ASSERT(sa.sa_handler == SIG_DFL);
    ASSERT(!sa.sa_restorer);

    sa = (struct sigaction){
        .sa_handler = handler2,
    };
    ASSERT_OK(sigaction(SIGUSR2, &sa, NULL));
    ASSERT_OK(kill(getpid(), SIGUSR2));
    ASSERT(sigusr2_received);

    return EXIT_SUCCESS;
}
