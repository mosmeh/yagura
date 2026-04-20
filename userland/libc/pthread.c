#include "private.h"
#include <err.h>
#include <linux/futex.h>
#include <panic.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

#define PTHREAD_RETURN(rc)                                                     \
    do {                                                                       \
        int __rc = (rc);                                                       \
        return IS_ERR(__rc) ? -__rc : 0;                                       \
    } while (0)

enum {
    STATE_JOINABLE,
    STATE_DETACHED,
    STATE_JOINABLE_EXITED,
    STATE_DETACHED_EXITED,
    STATE_JOINED,
};

struct pthread_attr {
    size_t guard_size;
    void* stack_addr;
    size_t stack_size;
    bool is_detached;
};

static struct pthread_attr default_attr(void) {
    return (struct pthread_attr){
        .guard_size = getauxval(AT_PAGESZ),
        .stack_size = 131072,
    };
}

static _Noreturn int thread_start(void* arg) {
    struct pthread* pth = arg;
    pthread_exit(pth->fn(pth->arg));
}

int pthread_create(pthread_t* thread, const pthread_attr_t* attrp,
                   void* (*start_routine)(void*), void* arg) {
    int ret = 0;

    struct pthread_attr attr = attrp ? **attrp : default_attr();

    void* alloc_base = NULL;
    if (!attr.stack_addr) {
        size_t alloc_size = attr.stack_size + attr.guard_size + __tls_size;
        alloc_base = malloc(alloc_size);
        if (!alloc_base) {
            ret = -ENOMEM;
            goto fail;
        }
        memset(alloc_base, 0, alloc_size);
        attr.stack_addr = alloc_base;
    }

    void* stack_top =
        (unsigned char*)attr.stack_addr + attr.stack_size - __tls_size;
    struct pthread* pth = __init_tls(stack_top);
    pth->state = attr.is_detached ? STATE_DETACHED : STATE_JOINABLE;
    pth->alloc_base = alloc_base;
    pth->fn = start_routine;
    pth->arg = arg;

    int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID |
                CLONE_CHILD_CLEARTID;
    ret =
        __clone(thread_start, stack_top, flags, pth, &pth->tid, &pth->tid, pth);
    if (IS_ERR(ret))
        goto fail;

    *thread = pth;
    return 0;

fail:
    free(alloc_base);
    PTHREAD_RETURN(ret);
}

static pid_t thread_tid(pthread_t pth) {
    return __atomic_load_n(&pth->tid, __ATOMIC_SEQ_CST);
}

NODISCARD static int futex_wait(void* uaddr, uint32_t val) {
    return __syscall(SYS_futex, (long)uaddr, FUTEX_WAIT, val, 0, 0, 0);
}

NODISCARD static int wait_for_exit(struct pthread* pth) {
    for (;;) {
        pid_t tid = thread_tid(pth);
        if (tid == 0)
            return 0;
        int ret = futex_wait(&pth->tid, tid);
        if (ret == -EAGAIN || ret == -EINTR)
            continue;
        if (IS_ERR(ret))
            return ret;
    }
}

NODISCARD static int free_thread_sync(struct pthread* pth) {
    int ret = wait_for_exit(pth);
    if (IS_ERR(ret))
        return ret;
    free(pth->alloc_base);
    return 0;
}

static _Atomic(struct pthread*) deferred_free_list;

static void free_thread_async(struct pthread* pth) {
    if (!pth->alloc_base)
        return;
    struct pthread* head = deferred_free_list;
    for (;;) {
        pth->next = head;
        if (atomic_compare_exchange_weak(&deferred_free_list, &head, pth))
            break;
    }
}

static void process_deferred_free(void) {
    struct pthread* pth = atomic_exchange(&deferred_free_list, NULL);
    while (pth) {
        struct pthread* next = pth->next;
        ASSERT_OK(free_thread_sync(pth));
        pth = next;
    }
}

int pthread_detach(pthread_t thread) {
    unsigned expected = STATE_JOINABLE;
    if (atomic_compare_exchange_strong(&thread->state, &expected,
                                       STATE_DETACHED))
        return 0;

    expected = STATE_JOINABLE_EXITED;
    if (atomic_compare_exchange_strong(&thread->state, &expected,
                                       STATE_DETACHED_EXITED)) {
        free_thread_async(thread);
        return 0;
    }

    return EINVAL;
}

void pthread_exit(void* retval) {
    process_deferred_free();

    struct pthread* pth = pthread_self();
    pth->retval = retval;

    unsigned state = STATE_JOINABLE;
    if (atomic_compare_exchange_strong(&pth->state, &state,
                                       STATE_JOINABLE_EXITED)) {
        // Freed by the joining thread
    } else {
        ASSERT(state == STATE_DETACHED);
        pth->state = STATE_DETACHED_EXITED;
        free_thread_async(pth);
    }

    SYSCALL1(exit, 0);
    UNREACHABLE();
}

int pthread_join(pthread_t thread, void** retval) {
    if (thread == pthread_self())
        return EDEADLK;

    for (;;) {
        unsigned state = STATE_JOINABLE_EXITED;
        if (atomic_compare_exchange_weak(&thread->state, &state,
                                         STATE_JOINED)) {
            if (retval)
                *retval = thread->retval;
            int ret = free_thread_sync(thread);
            if (IS_ERR(ret))
                PTHREAD_RETURN(ret);
            return 0;
        }
        switch (state) {
        case STATE_JOINABLE: {
            int ret = wait_for_exit(thread);
            if (IS_ERR(ret))
                PTHREAD_RETURN(ret);
            break;
        }
        case STATE_JOINABLE_EXITED:
            break; // Spurious failure. Retry
        case STATE_DETACHED:
        case STATE_DETACHED_EXITED:
            return EINVAL;
        case STATE_JOINED:
            return ESRCH;
        default:
            UNREACHABLE();
        }
    }
}

int pthread_equal(pthread_t t1, pthread_t t2) { return t1 == t2; }

int pthread_kill(pthread_t thread, int sig) {
    pid_t tid = thread_tid(thread);
    if (tid == 0)
        return ESRCH;
    PTHREAD_RETURN(SYSCALL2(tkill, tid, sig));
}

int pthread_sigmask(int how, const sigset_t* set, sigset_t* oldset) {
    PTHREAD_RETURN(
        SYSCALL4(rt_sigprocmask, how, set, oldset, sizeof(sigset_t)));
}

int pthread_attr_init(pthread_attr_t* attr) {
    struct pthread_attr* a = malloc(sizeof(struct pthread_attr));
    if (!a)
        return ENOMEM;
    *a = default_attr();
    *attr = a;
    return 0;
}

int pthread_attr_destroy(pthread_attr_t* attr) {
    free(*attr);
    return 0;
}

int pthread_attr_setguardsize(pthread_attr_t* attr, size_t guardsize) {
    (*attr)->guard_size = guardsize;
    return 0;
}

int pthread_attr_getguardsize(const pthread_attr_t* attr, size_t* guardsize) {
    *guardsize = (*attr)->guard_size;
    return 0;
}

int pthread_attr_setstack(pthread_attr_t* attr, void* stackaddr,
                          size_t stacksize) {
    if (stacksize < PTHREAD_STACK_MIN)
        return EINVAL;
    (*attr)->stack_addr = stackaddr;
    (*attr)->stack_size = stacksize;
    return 0;
}

int pthread_attr_getstack(const pthread_attr_t* attr, void** stackaddr,
                          size_t* stacksize) {
    *stackaddr = (*attr)->stack_addr;
    *stacksize = (*attr)->stack_size;
    return 0;
}

int pthread_attr_setstacksize(pthread_attr_t* attr, size_t stacksize) {
    if (stacksize < PTHREAD_STACK_MIN)
        return EINVAL;
    (*attr)->stack_size = stacksize;
    return 0;
}

int pthread_attr_getstacksize(const pthread_attr_t* attr, size_t* stacksize) {
    *stacksize = (*attr)->stack_size;
    return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t* attr, int detachstate) {
    switch (detachstate) {
    case PTHREAD_CREATE_JOINABLE:
        (*attr)->is_detached = false;
        return 0;
    case PTHREAD_CREATE_DETACHED:
        (*attr)->is_detached = true;
        return 0;
    }
    return EINVAL;
}

int pthread_attr_getdetachstate(const pthread_attr_t* attr, int* detachstate) {
    *detachstate = (*attr)->is_detached ? PTHREAD_CREATE_DETACHED
                                        : PTHREAD_CREATE_JOINABLE;
    return 0;
}
