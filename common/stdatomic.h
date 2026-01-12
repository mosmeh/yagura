#pragma once

typedef enum {
    memory_order_relaxed = __ATOMIC_RELAXED,
    memory_order_consume = __ATOMIC_CONSUME,
    memory_order_acquire = __ATOMIC_ACQUIRE,
    memory_order_release = __ATOMIC_RELEASE,
    memory_order_acq_rel = __ATOMIC_ACQ_REL,
    memory_order_seq_cst = __ATOMIC_SEQ_CST
} memory_order;

#ifndef __has_extension
#define __has_extension(x) 0
#endif

#if (__has_extension(c_atomic) || __has_extension(cxx_atomic)) &&              \
    defined(__clang__)
#define atomic_compare_exchange_strong_explicit(object, expected, desired,     \
                                                success, failure)              \
    __c11_atomic_compare_exchange_strong(object, expected, desired, success,   \
                                         failure)
#define atomic_compare_exchange_weak_explicit(object, expected, desired,       \
                                              success, failure)                \
    __c11_atomic_compare_exchange_weak(object, expected, desired, success,     \
                                       failure)
#define atomic_exchange_explicit(object, desired, order)                       \
    __c11_atomic_exchange(object, desired, order)
#define atomic_fetch_add_explicit(object, operand, order)                      \
    __c11_atomic_fetch_add(object, operand, order)
#define atomic_fetch_and_explicit(object, operand, order)                      \
    __c11_atomic_fetch_and(object, operand, order)
#define atomic_fetch_or_explicit(object, operand, order)                       \
    __c11_atomic_fetch_or(object, operand, order)
#define atomic_fetch_sub_explicit(object, operand, order)                      \
    __c11_atomic_fetch_sub(object, operand, order)
#define atomic_fetch_xor_explicit(object, operand, order)                      \
    __c11_atomic_fetch_xor(object, operand, order)
#define atomic_load_explicit(object, order) __c11_atomic_load(object, order)
#define atomic_store_explicit(object, desired, order)                          \
    __c11_atomic_store(object, desired, order)
#define atomic_thread_fence(order) __c11_atomic_thread_fence(order)
#define atomic_signal_fence(order) __c11_atomic_signal_fence(order)
#else
#define atomic_compare_exchange_strong_explicit(object, expected, desired,     \
                                                success, failure)              \
    __atomic_compare_exchange_n(object, expected, desired, 0, success, failure)
#define atomic_compare_exchange_weak_explicit(object, expected, desired,       \
                                              success, failure)                \
    __atomic_compare_exchange_n(object, expected, desired, 1, success, failure)
#define atomic_exchange_explicit(object, desired, order)                       \
    __atomic_exchange_n(object, desired, order)
#define atomic_fetch_add_explicit(object, operand, order)                      \
    __atomic_fetch_add(object, operand, order)
#define atomic_fetch_and_explicit(object, operand, order)                      \
    __atomic_fetch_and(object, operand, order)
#define atomic_fetch_or_explicit(object, operand, order)                       \
    __atomic_fetch_or(object, operand, order)
#define atomic_fetch_sub_explicit(object, operand, order)                      \
    __atomic_fetch_sub(object, operand, order)
#define atomic_fetch_xor_explicit(object, operand, order)                      \
    __atomic_fetch_xor(object, operand, order)
#define atomic_load_explicit(object, order) __atomic_load_n(object, order)
#define atomic_store_explicit(object, desired, order)                          \
    __atomic_store_n(object, desired, order)
#define atomic_thread_fence(order) __atomic_thread_fence(order)
#define atomic_signal_fence(order) __atomic_signal_fence(order)
#endif

#define atomic_compare_exchange_strong(object, expected, desired)              \
    atomic_compare_exchange_strong_explicit(                                   \
        object, expected, desired, memory_order_seq_cst, memory_order_seq_cst)
#define atomic_compare_exchange_weak(object, expected, desired)                \
    atomic_compare_exchange_weak_explicit(                                     \
        object, expected, desired, memory_order_seq_cst, memory_order_seq_cst)
#define atomic_exchange(object, desired)                                       \
    atomic_exchange_explicit(object, desired, memory_order_seq_cst)
#define atomic_fetch_add(object, operand)                                      \
    atomic_fetch_add_explicit(object, operand, memory_order_seq_cst)
#define atomic_fetch_and(object, operand)                                      \
    atomic_fetch_and_explicit(object, operand, memory_order_seq_cst)
#define atomic_fetch_or(object, operand)                                       \
    atomic_fetch_or_explicit(object, operand, memory_order_seq_cst)
#define atomic_fetch_sub(object, operand)                                      \
    atomic_fetch_sub_explicit(object, operand, memory_order_seq_cst)
#define atomic_fetch_xor(object, operand)                                      \
    atomic_fetch_xor_explicit(object, operand, memory_order_seq_cst)
#define atomic_load(object) atomic_load_explicit(object, memory_order_seq_cst)
#define atomic_store(object, desired)                                          \
    atomic_store_explicit(object, desired, memory_order_seq_cst)
