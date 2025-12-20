#pragma once

#include <signal.h>
#include <stddef.h>
#include <stdnoreturn.h>

#define PTHREAD_STACK_MIN 16384

typedef struct pthread* pthread_t;
typedef struct pthread_attr* pthread_attr_t;

int pthread_create(pthread_t* restrict thread,
                   const pthread_attr_t* restrict attr,
                   void* (*start_routine)(void*), void* restrict arg);
int pthread_detach(pthread_t thread);
noreturn void pthread_exit(void* retval);
int pthread_join(pthread_t thread, void** retval);

pthread_t pthread_self(void);
int pthread_equal(pthread_t t1, pthread_t t2);

int pthread_kill(pthread_t thread, int sig);
int pthread_sigmask(int how, const sigset_t* set, sigset_t* oldset);

int pthread_attr_init(pthread_attr_t* attr);
int pthread_attr_destroy(pthread_attr_t* attr);

int pthread_attr_setguardsize(pthread_attr_t* attr, size_t guardsize);
int pthread_attr_getguardsize(const pthread_attr_t* restrict attr,
                              size_t* restrict guardsize);

int pthread_attr_setstack(pthread_attr_t* attr, void* stackaddr,
                          size_t stacksize);
int pthread_attr_getstack(const pthread_attr_t* restrict attr,
                          void** restrict stackaddr,
                          size_t* restrict stacksize);

int pthread_attr_setstacksize(pthread_attr_t* attr, size_t stacksize);
int pthread_attr_getstacksize(const pthread_attr_t* restrict attr,
                              size_t* restrict stacksize);

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

int pthread_attr_setdetachstate(pthread_attr_t* attr, int detachstate);
int pthread_attr_getdetachstate(const pthread_attr_t* attr, int* detachstate);
