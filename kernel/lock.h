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
    unsigned int level;
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
// DEFINE_LOCK_GUARD(mutex, struct mutex)
//
// void use_lock(void) {
//     SCOPED_LOCK(mutex, lock);
//     // mutex_unlock(lock) is called at the end of the scope
// }

// NOLINTBEGIN(bugprone-macro-parentheses)
#define DEFINE_LOCK_GUARD(name, type)                                          \
    struct __LOCK_GUARD_ID(name) {                                             \
        type* obj;                                                             \
    };                                                                         \
                                                                               \
    static inline void __LOCK_GUARD_UNLOCK(name)(                              \
        struct __LOCK_GUARD_ID(name) * guard) {                                \
        if (guard->obj) {                                                      \
            __UNLOCK(name)(guard->obj);                                        \
            guard->obj = NULL;                                                 \
        }                                                                      \
    }
// NOLINTEND(bugprone-macro-parentheses)

#define __LOCK_GUARD_ID(name) CONCAT(__, CONCAT(name, _lock_guard))
#define __LOCK_GUARD_UNLOCK(name) __UNLOCK(__LOCK_GUARD_ID(name))

#define SCOPED_LOCK(name, obj)                                                 \
    __LOCK(name)(obj);                                                         \
    struct __LOCK_GUARD_ID(name) __SCOPED_LOCK_UNIQUE(name)                    \
        CLEANUP(__LOCK_GUARD_UNLOCK(name)) = {obj};

#define __SCOPED_LOCK_UNIQUE(name) CONCAT(__LOCK_GUARD_ID(name), __COUNTER__)

DEFINE_LOCK_GUARD(mutex, struct mutex)
DEFINE_LOCK_GUARD(spinlock, struct spinlock)

// Locked resource helper macro
//
// struct obj {
//     struct mutex lock;
// }
//
// DEFINE_LOCKED(obj, struct obj, mutex, lock)
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

// NOLINTBEGIN(bugprone-macro-parentheses)
#define DEFINE_LOCKED(name, type, lock_type, lock_field)                       \
    MAYBE_UNUSED static inline void __LOCK(name)(type * obj) {                 \
        ASSERT_PTR(obj);                                                       \
        __LOCK(lock_type)(&obj->lock_field);                                   \
    }                                                                          \
                                                                               \
    MAYBE_UNUSED static inline void __UNLOCK(name)(type * obj) {               \
        ASSERT_PTR(obj);                                                       \
        __UNLOCK(lock_type)(&obj->lock_field);                                 \
    }                                                                          \
                                                                               \
    MAYBE_UNUSED static inline bool __CURRENT_LOCKS(name)(const type* obj) {   \
        ASSERT_PTR(obj);                                                       \
        return __CURRENT_LOCKS(lock_type)(&obj->lock_field);                   \
    }                                                                          \
                                                                               \
    DEFINE_LOCK_GUARD(name, type)
// NOLINTEND(bugprone-macro-parentheses)
