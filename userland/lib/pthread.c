#include "pthread.h"
#include "panic.h"
#include "private.h"
#include "sched.h"
#include "stdlib.h"
#include "string.h"
#include "sys/auxv.h"
#include <asm/ldt.h>

#define PTHREAD_RETURN(rc)                                                     \
    do {                                                                       \
        int _rc = (rc);                                                        \
        return IS_ERR(_rc) ? -_rc : 0;                                         \
    } while (0)

enum {
    STATE_JOINABLE,
    STATE_DETACHED,
    STATE_EXITED,
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

static noreturn int thread_start(void* arg) {
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

    uint16_t gs;
    __asm__ volatile("movw %%gs, %0" : "=r"(gs));
    struct user_desc tls_desc = {
        .entry_number = gs / 8,
        .base_addr = (unsigned)pth,
        .limit = 0xfffff,
        .seg_32bit = 1,
        .limit_in_pages = 1,
    };

    int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID;
    ret = __clone(thread_start, stack_top, flags, pth, &pth->tid, &tls_desc,
                  NULL);
    if (IS_ERR(ret))
        goto fail;

    *thread = pth;
    return 0;

fail:
    free(alloc_base);
    PTHREAD_RETURN(ret);
}

int pthread_detach(pthread_t thread) {
    unsigned expected = STATE_JOINABLE;
    if (!atomic_compare_exchange_strong(&thread->state, &expected,
                                        STATE_DETACHED))
        return EINVAL;
    return 0;
}

void pthread_exit(void* retval) {
    struct pthread* pth = pthread_self();
    pth->retval = retval;
    unsigned state = atomic_exchange(&pth->state, STATE_EXITED);
    switch (state) {
    case STATE_JOINABLE:
        break;
    case STATE_DETACHED:
        free(pth->alloc_base);
        break;
    default:
        UNREACHABLE();
    }
    SYSCALL1(exit, 0);
    UNREACHABLE();
}

int pthread_join(pthread_t thread, void** retval) {
    for (;;) {
        switch (thread->state) {
        case STATE_JOINABLE:
            break;
        case STATE_DETACHED:
            return EINVAL;
        case STATE_EXITED:
            goto exit;
        default:
            UNREACHABLE();
        }
        sched_yield();
    }
exit:
    if (retval)
        *retval = thread->retval;
    free(thread->alloc_base);
    return 0;
}

pthread_t pthread_self(void) {
    pthread_t pth;
    __asm__ volatile("movl %%gs:0, %0" : "=r"(pth));
    return pth;
}

int pthread_equal(pthread_t t1, pthread_t t2) { return t1 == t2; }

int pthread_kill(pthread_t thread, int sig) {
    PTHREAD_RETURN(SYSCALL2(kill, thread->tid, sig));
}

int pthread_sigmask(int how, const sigset_t* set, sigset_t* oldset) {
    PTHREAD_RETURN(SYSCALL3(sigprocmask, how, set, oldset));
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
