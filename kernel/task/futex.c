#include <kernel/memory/safe_string.h>
#include <kernel/memory/vm.h>
#include <kernel/task/futex.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

struct futex_key {
    // User address for private futexes.
    // Offset within vm_obj for shared futexes.
    uint64_t offset;

    struct tree* tree;     // &vm->futexes or &vm_obj->futexes
    struct vm_obj* vm_obj; // NULL for private futexes
};

static void futex_key_lock(struct futex_key* key) {
    vm_lock(current->vm);
    if (key->vm_obj)
        vm_obj_lock(key->vm_obj);
}

static void futex_key_unlock(struct futex_key* key) {
    if (key->vm_obj)
        vm_obj_unlock(key->vm_obj);
    vm_unlock(current->vm);
}

static bool futex_key_is_locked_by_current(const struct futex_key* key) {
    if (!vm_is_locked_by_current(current->vm))
        return false;
    if (key->vm_obj && !vm_obj_is_locked_by_current(key->vm_obj))
        return false;
    return true;
}

DEFINE_LOCK_GUARD(futex_key, struct futex_key)

typedef long (*futex_op_fn)(struct futex_key*, uint32_t* uaddr, uint32_t val,
                            const struct timespec* deadline, uint32_t* uaddr2,
                            uint32_t val3, int flags);

NODISCARD static long invoke_op(futex_op_fn op, struct futex_key* key,
                                uint32_t* uaddr, uint32_t val,
                                const struct timespec* deadline,
                                uint32_t* uaddr2, uint32_t val3, int flags) {
    ASSERT(futex_key_is_locked_by_current(key));
    // op is responsible for unlocking the key.
    return op(key, uaddr, val, deadline, uaddr2, val3, flags);
}

// NOLINTBEGIN(readability-non-const-parameter)
NODISCARD static long do_futex(futex_op_fn op, uint32_t* uaddr, uint32_t val,
                               const struct timespec* deadline,
                               uint32_t* uaddr2, uint32_t val3, int flags) {
    // NOLINTEND(readability-non-const-parameter)
    (void)uaddr2;
    (void)val3;

    if (!is_user_range(uaddr, sizeof(uint32_t)))
        return -EFAULT;
    if ((uintptr_t)uaddr % sizeof(uint32_t) != 0)
        return -EINVAL;

    struct vm* vm = current->vm;
    vm_lock(vm);

    if (flags & FUTEX_PRIVATE_FLAG) {
        struct futex_key key = {
            .offset = (uintptr_t)uaddr,
            .tree = &vm->futexes,
        };
        return invoke_op(op, &key, uaddr, val, deadline, uaddr2, val3, flags);
    }

    struct vm_region* region = vm_find(vm, uaddr);
    if (!region) {
        vm_unlock(vm);
        return -EFAULT;
    }

    struct vm_obj* vm_obj = region->obj;
    if (!vm_obj) {
        vm_unlock(vm);
        return -EFAULT;
    }

    if (!(region->flags & VM_SHARED)) {
        struct futex_key key = {
            .offset = (uintptr_t)uaddr,
            .tree = &vm->futexes,
        };
        return invoke_op(op, &key, uaddr, val, deadline, uaddr2, val3, flags);
    }

    struct futex_key key = {
        .offset = (uintptr_t)uaddr - (uintptr_t)vm_region_to_virt(region) +
                  ((uint64_t)region->offset << PAGE_SHIFT),
        .tree = &vm_obj->futexes,
        .vm_obj = vm_obj_ref(vm_obj),
    };
    vm_obj_lock(vm_obj);
    long rc = invoke_op(op, &key, uaddr, val, deadline, uaddr2, val3, flags);
    vm_obj_unref(vm_obj);
    return rc;
}

// NOLINTBEGIN(readability-non-const-parameter)
long futex(uint32_t* uaddr, int op, uint32_t val,
           const struct timespec* timeout, uint32_t* uaddr2, uint32_t val3) {
    // NOLINTEND(readability-non-const-parameter)
    (void)uaddr2;

    if (timeout && futex_op_has_timeout(op) && !timespec_is_valid(timeout))
        return -EINVAL;

    int flags = op & ~FUTEX_CMD_MASK;
    switch (op & FUTEX_CMD_MASK) {
    case FUTEX_WAIT:
        return futex_wait(uaddr, val, timeout, flags);
    case FUTEX_WAKE:
        return futex_wake(uaddr, val, flags);
    case FUTEX_WAIT_BITSET:
        return futex_wait_bitset(uaddr, val, timeout, val3, flags);
    case FUTEX_WAKE_BITSET:
        return futex_wake_bitset(uaddr, val, val3, flags);
    default:
        return -ENOSYS;
    }
}

bool futex_op_has_timeout(int op) {
    switch (op & FUTEX_CMD_MASK) {
    case FUTEX_WAIT:
    case FUTEX_WAIT_BITSET:
        return true;
    default:
        return false;
    }
}

static clockid_t flags_to_clock_id(int flags) {
    if (flags & FUTEX_CLOCK_REALTIME)
        return CLOCK_REALTIME;
    return CLOCK_MONOTONIC;
}

struct futex_waiter {
    struct futex_key* key;
    struct waiter* waiter;
    struct timer timer;
    struct tree_node node;
    uint32_t bitset;
    bool futex_woken;
};

// NOLINTBEGIN(readability-non-const-parameter)
static long wait_bitset(struct futex_key* key, uint32_t* uaddr, uint32_t val,
                        const struct timespec* deadline, uint32_t* uaddr2,
                        uint32_t bitset, int flags) {
    // NOLINTEND(readability-non-const-parameter)
    (void)uaddr2;

    uint32_t uval;
    int rc = atomic_load_u32_from_user(uaddr, &uval);
    if (IS_ERR(rc)) {
        futex_key_unlock(key);
        return rc;
    }
    if (uval != val) {
        futex_key_unlock(key);
        return -EAGAIN;
    }

    struct futex_waiter futex_waiter = {
        .key = key,
        .bitset = bitset,
    };

    struct timer* timer = &futex_waiter.timer;
    ASSERT_OK(timer_init(timer, flags_to_clock_id(flags), NULL));

    struct tree_node** new_node = &key->tree->root;
    struct tree_node* parent = NULL;
    while (*new_node) {
        parent = *new_node;
        struct futex_waiter* w =
            CONTAINER_OF(parent, struct futex_waiter, node);
        if (key->offset < w->key->offset) {
            new_node = &parent->left;
        } else {
            // New waiters with the same offset are ordered after existing ones
            // to ensure FIFO wakeup order.
            new_node = &parent->right;
        }
    }
    *new_node = &futex_waiter.node;
    tree_insert(key->tree, parent, *new_node);

    {
        SCOPED_WAIT(waiter, &timer->wait);
        futex_waiter.waiter = &waiter;
        if (deadline)
            timer_arm_at(timer, deadline);
        futex_key_unlock(key);
        rc = waiter_wait_interruptible(&waiter);
        timer_disarm(timer);

        SCOPED_LOCK(futex_key, key);
        tree_remove(key->tree, &futex_waiter.node);
    }
    if (futex_waiter.futex_woken)
        return 0;
    if (IS_ERR(rc))
        return rc;
    return -ETIMEDOUT;
}

int futex_wait(uint32_t* uaddr, uint32_t val, const struct timespec* timeout,
               int flags) {
    if (timeout && !timespec_is_valid(timeout))
        return -EINVAL;
    if (flags & ~FUTEX_PRIVATE_FLAG)
        return -ENOSYS;
    struct timespec deadline;
    if (timeout) {
        ASSERT_OK(time_now(flags_to_clock_id(flags), &deadline));
        timespec_add(&deadline, timeout);
    }
    return futex_wait_bitset(uaddr, val, timeout ? &deadline : NULL,
                             FUTEX_BITSET_MATCH_ANY, flags);
}

int futex_wait_bitset(uint32_t* uaddr, uint32_t val,
                      const struct timespec* deadline, uint32_t bitset,
                      int flags) {
    if (deadline && !timespec_is_valid(deadline))
        return -EINVAL;
    if (flags & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME))
        return -ENOSYS;
    if (!bitset)
        return -EINVAL;
    return do_futex(wait_bitset, uaddr, val, deadline, NULL, bitset, flags);
}

// NOLINTBEGIN(readability-non-const-parameter)
static long wake_bitset(struct futex_key* key, uint32_t* uaddr,
                        uint32_t num_to_wake, const struct timespec* deadline,
                        uint32_t* uaddr2, uint32_t bitset, int flags) {
    // NOLINTEND(readability-non-const-parameter)
    (void)uaddr;
    (void)deadline;
    (void)uaddr2;
    (void)flags;

    // Find the first waiter with the same offset.
    struct tree_node* node = key->tree->root;
    struct futex_waiter* futex_waiter = NULL;
    while (node) {
        struct futex_waiter* w = CONTAINER_OF(node, struct futex_waiter, node);
        if (key->offset <= w->key->offset) {
            futex_waiter = w;
            node = node->left;
        } else if (key->offset > w->key->offset) {
            node = node->right;
        }
    }

    size_t num_woken = 0;
    while (num_woken < num_to_wake && futex_waiter &&
           futex_waiter->key->offset == key->offset) {
        struct tree_node* next = tree_next(&futex_waiter->node);
        if ((futex_waiter->bitset & bitset) &&
            waiter_wake(futex_waiter->waiter)) {
            tree_remove(key->tree, &futex_waiter->node);
            futex_waiter->futex_woken = true;
            ++num_woken;
        }
        if (!next)
            break;
        futex_waiter = CONTAINER_OF(next, struct futex_waiter, node);
    }

    futex_key_unlock(key);

    return num_woken;
}

ssize_t futex_wake(uint32_t* uaddr, uint32_t val, int flags) {
    return futex_wake_bitset(uaddr, val, FUTEX_BITSET_MATCH_ANY, flags);
}

ssize_t futex_wake_bitset(uint32_t* uaddr, uint32_t val, uint32_t bitset,
                          int flags) {
    if (flags & ~FUTEX_PRIVATE_FLAG)
        return -ENOSYS;
    if (!bitset)
        return -EINVAL;
    return do_futex(wake_bitset, uaddr, val, NULL, NULL, bitset, flags);
}
