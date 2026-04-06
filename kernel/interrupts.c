#include <kernel/arch/system.h>
#include <kernel/interrupts.h>

struct handler {
    interrupt_handler_fn fn;
    void* ctx;
    struct handler* next;
};

static bool handler_eq(const struct handler* handler, interrupt_handler_fn fn,
                       void* ctx) {
    return handler->fn == fn && handler->ctx == ctx;
}

struct slot {
    struct handler* handlers;
};

static struct slot slots[UINT8_MAX + 1];

static struct handler* alloc_handler(interrupt_handler_fn fn, void* ctx) {
    // Use a statically allocated pool of handlers to allow registering handlers
    // before the kmalloc is available.
    static struct handler handlers[ARRAY_SIZE(slots) * 4];
    for (size_t i = 0; i < ARRAY_SIZE(handlers); ++i) {
        if (!handlers[i].fn) {
            handlers[i] = (struct handler){
                .fn = fn,
                .ctx = ctx,
            };
            return &handlers[i];
        }
    }
    PANIC("Out of interrupt handlers");
}

bool interrupt_register(uint8_t num, interrupt_handler_fn fn, void* ctx) {
    ASSERT(!arch_smp_active());
    ASSERT_PTR(fn);

    SCOPED_DISABLE_INTERRUPTS();
    struct slot* slot = &slots[num];
    struct handler* handler = slot->handlers;
    struct handler* prev = NULL;
    while (handler) {
        if (handler_eq(handler, fn, ctx))
            return false;
        prev = handler;
        handler = handler->next;
    }
    struct handler* new_handler = alloc_handler(fn, ctx);
    if (prev)
        prev->next = new_handler;
    else
        slot->handlers = new_handler;
    return true;
}

bool interrupt_unregister(uint8_t num, interrupt_handler_fn fn, void* ctx) {
    ASSERT(!arch_smp_active());
    ASSERT_PTR(fn);

    SCOPED_DISABLE_INTERRUPTS();
    struct slot* slot = &slots[num];
    struct handler* handler = slot->handlers;
    struct handler* prev = NULL;
    while (handler) {
        if (handler_eq(handler, fn, ctx)) {
            if (prev)
                prev->next = handler->next;
            else
                slot->handlers = handler->next;
            *handler = (struct handler){0};
            return true;
        }
        prev = handler;
        handler = handler->next;
    }
    return false;
}

bool interrupt_handle(uint8_t num, struct registers* regs) {
    struct slot* slot = &slots[num];
    if (!slot->handlers)
        return false;
    for (struct handler* handler = slot->handlers; handler;
         handler = handler->next)
        handler->fn(regs, handler->ctx);
    return true;
}
