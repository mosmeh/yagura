#pragma once

#include <kernel/panic.h>
#include <stdatomic.h>

// Reference counting rules:
//
// - When a resource is created, its reference count is initialized to 1.
//   Use REFCOUNT_INIT_ONE for this.
//
//   struct obj* create_obj(...) {
//       struct obj* obj = malloc(sizeof(struct obj));
//       *obj = (struct obj){
//           .refcount = REFCOUNT_INIT_ONE,
//       };
//       return obj;
//   }
//
// - When a function returns a resource, it increments the count before
//   returning it. The caller is then responsible for decrementing the count
//   when it is done with the resource.
//
//   struct obj* lookup_obj(...) {
//       refcount_inc(&obj->refcount);
//       return obj;
//   }
//   struct obj* obj = lookup_obj(...);
//   // Use obj
//   refcount_dec(&obj->refcount);
//
// - When a function takes a resource as an argument, the caller is responsible
//   for keeping the resource alive for the duration of the call.
//   The caller does not need to increment the count before passing it in.
//   The callee increments the count if it needs to keep the resource beyond
//   the duration of the call.
//
//   void use_obj(struct obj* obj) {
//       // Use obj
//       refcount_inc(&obj->refcount); // If we need to keep it
//       // Store obj somewhere for later use
//   }
//   use_obj(obj);

#define REFCOUNT_INIT(n) {.count = (n)}
#define REFCOUNT_INIT_ONE REFCOUNT_INIT(1)

typedef struct refcount {
    atomic_size_t count;
} refcount_t;

static inline size_t refcount_get(const refcount_t* refcount) {
    ASSERT(refcount);
    return atomic_load(&refcount->count);
}

// Returns the new reference count.
static inline size_t refcount_inc(refcount_t* refcount) {
    ASSERT(refcount);
    size_t c = atomic_fetch_add(&refcount->count, 1);
    ASSERT(c > 0);
    return c + 1;
}

// Returns the new reference count.
static inline size_t refcount_inc_allowing_zero(refcount_t* refcount) {
    ASSERT(refcount);
    return atomic_fetch_add(&refcount->count, 1) + 1;
}

// Returns the new reference count.
static inline size_t refcount_dec(refcount_t* refcount) {
    ASSERT(refcount);
    ASSERT(refcount_get(refcount) > 0);
    size_t c = atomic_fetch_sub(&refcount->count, 1);
    ASSERT(c > 0);
    return c - 1;
}

// Reference counting helper macros
//
// struct base_obj {
//     refcount_t refcount;
// };
//
// void __base_obj_destroy(struct base_obj*);
// DEFINE_REFCOUNTED_BASE(base_obj, struct base_obj*, refcount,
//                        __base_obj_destroy)
//
// struct sub_obj {
//    struct base_obj base;
// };
// DEFINE_REFCOUNTED_SUB(sub_obj, struct sub_obj*, base_obj, base)
//
// void use_obj(void) {
//     struct base_obj* base_obj = create_base_obj(...);
//     struct base_obj* base_obj2 = base_obj_ref(obj);
//     struct sub_obj* sub_obj = create_sub_obj(...);
//     // Use objects
//     sub_obj_unref(sub_obj);
//     base_obj_unref(base_obj2);
//     base_obj_unref(base_obj);
//  }

#define DEFINE_REFCOUNTED_BASE(name, type, field, destructor)                  \
    static inline type name##_ref(type obj) {                                  \
        ASSERT(obj);                                                           \
        refcount_inc(&obj->field);                                             \
        return obj;                                                            \
    }                                                                          \
                                                                               \
    static inline void name##_unref(type obj) {                                \
        if (!obj)                                                              \
            return;                                                            \
        if (refcount_dec(&obj->field))                                         \
            return;                                                            \
        destructor(obj);                                                       \
    }                                                                          \
                                                                               \
    DEFINE_FREE(name, type, name##_unref)

#define DEFINE_REFCOUNTED_SUB(name, type, base_type, base_field)               \
    static inline type name##_ref(type obj) {                                  \
        ASSERT(obj);                                                           \
        base_type##_ref(&obj->base_field);                                     \
        return obj;                                                            \
    }                                                                          \
                                                                               \
    static inline void name##_unref(type obj) {                                \
        if (!obj)                                                              \
            return;                                                            \
        base_type##_unref(&obj->base_field);                                   \
    }                                                                          \
                                                                               \
    DEFINE_FREE(name, type, name##_unref)

// Scoped resource management macros
//
// DEFINE_FREE(obj, struct obj*, obj_unref)
//
// struct obj* foo(void) {
//     struct obj* obj FREE(obj) = create_obj(...);
//     // Use obj
//     if (...)
//         return TAKE_PTR(obj); // Return obj without unref
//     // When obj goes out of scope, obj_unref(obj) is called automatically
// }

#define DEFINE_FREE(name, type, func)                                          \
    static inline void __free_##name(void* p) {                                \
        type _p = *(type*)p;                                                   \
        if (_p && IS_OK(_p))                                                   \
            func(_p);                                                          \
    }

#define CLEANUP(func) __attribute__((__cleanup__(func)))
#define FREE(name) CLEANUP(__free_##name)

#define __TAKE_PTR(ptr, nullvalue)                                             \
    ({                                                                         \
        __typeof__(ptr)* __ptr = &(ptr);                                       \
        __typeof__(ptr) __val = *__ptr;                                        \
        *__ptr = nullvalue;                                                    \
        __val;                                                                 \
    })
#define TAKE_PTR(ptr) ((__typeof__(ptr))__TAKE_PTR(ptr, NULL))
