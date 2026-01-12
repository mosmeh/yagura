#pragma once

#include <common/macros.h>
#include <common/stdbool.h>
#include <common/stddef.h>
#include <common/stdint.h>

#define DEFINE_LOCK(name)                                                      \
    void __LOCK(name)(struct name*);                                           \
    void __UNLOCK(name)(struct name*);                                         \
    bool __CURRENT_LOCKS(name)(const struct name*);

#define __LOCK(name) CONCAT(name, _lock)
#define __UNLOCK(name) CONCAT(name, _unlock)
#define __CURRENT_LOCKS(name) CONCAT(name, _is_locked_by_current)

struct mutex {
    _Atomic(struct task*) holder;
    _Atomic(unsigned int) level;
    _Atomic(bool) lock;
};

DEFINE_LOCK(mutex)

struct spinlock {
    _Atomic(unsigned int) level;
    _Atomic(unsigned int) lock;
};

DEFINE_LOCK(spinlock)

// Lock guard helper macros
//
// struct mutex lock;
// DEFINE_LOCK_GUARD(mutex, struct mutex, mutex, lock)
//
// void use_lock(void) {
//     SCOPED_LOCK(mutex, lock);
//     // mutex_unlock(lock) is called at the end of the scope
// }

#define DEFINE_LOCK_GUARD(name, type, lock, unlock)                            \
    struct __LOCK_GUARD_ID(name) {                                             \
        type obj;                                                              \
    };                                                                         \
                                                                               \
    static inline void __LOCK_GUARD_UNLOCK(name)(void* p) {                    \
        struct __LOCK_GUARD_ID(name)* guard = p;                               \
        if (guard->obj) {                                                      \
            __UNLOCK(name)(guard->obj);                                        \
            guard->obj = NULL;                                                 \
        }                                                                      \
    }

#define __LOCK_GUARD_ID(name) CONCAT(__, CONCAT(name, _lock_guard))
#define __LOCK_GUARD_UNLOCK(name) CONCAT(__LOCK_GUARD_ID(name), _unlock)

#define SCOPED_LOCK(name, obj)                                                 \
    __LOCK(name)(obj);                                                         \
    struct __LOCK_GUARD_ID(name) __SCOPED_LOCK_UNIQUE(name)                    \
        CLEANUP(__LOCK_GUARD_UNLOCK(name)) = {obj};

#define __SCOPED_LOCK_UNIQUE(name) CONCAT(__LOCK_GUARD_ID(name), __COUNTER__)

DEFINE_LOCK_GUARD(mutex, struct mutex*, mutex, lock)
DEFINE_LOCK_GUARD(spinlock, struct spinlock*, spinlock, lock)

// Locked resource helper macro
//
// struct obj {
//     struct mutex lock;
// }
//
// DEFINE_LOCKED(obj, struct obj*, mutex, lock)
//
// void manual_lock(void) {
//     struct obj* x = create_obj(...);
//     obj_lock(x);
//     // Use x
//     obj_unlock(x);
// }
//
// void scoped_lock(void) {
//     struct obj* x = create_obj(...);
//     SCOPED_LOCK(obj, x);
//     // obj_unlock(x) is called at the end of the scope
// }

#define DEFINE_LOCKED(name, type, lock_type, lock_field)                       \
    MAYBE_UNUSED static inline void __LOCK(name)(type obj) {                   \
        ASSERT(obj);                                                           \
        lock_type##_lock(&obj->lock_field);                                    \
    }                                                                          \
                                                                               \
    MAYBE_UNUSED static inline void __UNLOCK(name)(type obj) {                 \
        ASSERT(obj);                                                           \
        lock_type##_unlock(&obj->lock_field);                                  \
    }                                                                          \
                                                                               \
    MAYBE_UNUSED static inline bool __CURRENT_LOCKS(name)(const type obj) {    \
        ASSERT(obj);                                                           \
        return CONCAT(lock_type, _is_locked_by_current)(&obj->lock_field);     \
    }                                                                          \
                                                                               \
    DEFINE_LOCK_GUARD(name, type, lock_type, lock_field)
