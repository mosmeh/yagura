#include <kernel/api/sys/syscall.h>
#include <kernel/arch/x86/interrupts/interrupts.h>
#include <kernel/arch/x86/interrupts/isr_stubs.h>
#include <kernel/arch/x86/memory/page_fault.h>
#include <kernel/arch/x86/task/context.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/task/task.h>

#define TASK_GATE 0x5
#define INTERRUPT_GATE16 0x6
#define TRAP_GATE16 0x7
#define INTERRUPT_GATE32 0xe
#define TRAP_GATE32 0xf

struct idt_gate {
    uint16_t base_lo : 16;
    uint16_t selector : 16;
    uint8_t interrupt_stack_table : 3;
    uint8_t reserved1 : 5;
    uint8_t gate_type : 4;
    uint8_t reserved2 : 1;
    uint8_t dpl : 2;
    uint8_t present : 1;
    uint16_t base_hi : 16;
};

struct idtr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

#define NUM_IDT_ENTRIES 256

static struct idt_gate idt[NUM_IDT_ENTRIES];
static struct idtr idtr = {
    .limit = sizeof(idt) - 1,
    .base = (uintptr_t)idt,
};
static interrupt_handler_fn interrupt_handlers[NUM_IDT_ENTRIES];

void arch_interrupts_set_handler(uint8_t num, interrupt_handler_fn handler) {
    interrupt_handlers[num] = handler;
}

void isr_handler(struct registers* regs) {
    ASSERT(regs->interrupt_num < NUM_IDT_ENTRIES);

    if (regs->interrupt_num != SPURIOUS_VECTOR) {
        if (regs->interrupt_num != SYSCALL_VECTOR)
            lapic_eoi();

        uint32_t irq = regs->interrupt_num - IRQ(0);
        if (irq < NUM_IRQS)
            i8259_eoi(irq);
    }

    cpu_process_messages();

    if (regs->interrupt_num != SPURIOUS_VECTOR) {
        interrupt_handler_fn handler = interrupt_handlers[regs->interrupt_num];
        if (handler)
            handler(regs);
    }
}

static void set_gate(uint8_t index, uintptr_t base, uint16_t selector,
                     uint8_t gate_type, uint8_t dpl) {
    idt[index] = (struct idt_gate){
        .base_lo = base & 0xffff,
        .base_hi = (base >> 16) & 0xffff,
        .selector = selector,
        .gate_type = gate_type & 0xf,
        .dpl = dpl & 0x3,
        .present = 1,
    };
}

void idt_set_gate_user_callable(uint8_t index) {
    struct idt_gate* entry = idt + index;
    entry->gate_type = TRAP_GATE32;
    entry->dpl = 3;
}

void idt_flush(void) { __asm__ volatile("lidt %0" ::"m"(idtr) : "memory"); }

static void dump_context(const struct registers* regs) {
    arch_dump_registers(regs);
    dump_stack_trace(regs->ip, regs->bp);
}

static _Noreturn void crash(const struct registers* regs, int signum) {
    dump_context(regs);

    if (!arch_is_user_mode(regs))
        PANIC("Kernel crashed");

    task_crash(signum);
}

#define DEFINE_ISR_WITHOUT_ERROR_CODE(num)                                     \
    void isr##num(void);                                                       \
    __asm__("isr" #num ":\n"                                                   \
            "push $0\n"                                                        \
            "push $" #num "\n"                                                 \
            "jmp isr_entry\n");

#define DEFINE_ISR_WITH_ERROR_CODE(num)                                        \
    void isr##num(void);                                                       \
    __asm__("isr" #num ":\n"                                                   \
            "push $" #num "\n"                                                 \
            "jmp isr_entry\n");

#define DEFINE_EXCEPTION(num, msg)                                             \
    static void handle_exception##num(struct registers* regs) {                \
        kprint("Exception: " msg "\n");                                        \
        dump_context(regs);                                                    \
        PANIC("Unrecoverable exception");                                      \
    }

#define DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(num, msg)                          \
    DEFINE_ISR_WITHOUT_ERROR_CODE(num)                                         \
    DEFINE_EXCEPTION(num, msg)

#define DEFINE_EXCEPTION_WITH_ERROR_CODE(num, msg)                             \
    DEFINE_ISR_WITH_ERROR_CODE(num)                                            \
    DEFINE_EXCEPTION(num, msg)

DEFINE_ISR_WITHOUT_ERROR_CODE(0)
static void handle_exception0(struct registers* regs) {
    kprint("Divide-by-zero error\n");
    crash(regs, SIGFPE);
}

DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(1, "Debug")
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(2, "Non-maskable interrupt")
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(3, "Breakpoint")
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(4, "Overflow")
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(5, "Bound range exceeded")

DEFINE_ISR_WITHOUT_ERROR_CODE(6)
static void handle_exception6(struct registers* regs) {
    kprint("Invalid opcode\n");
    crash(regs, SIGILL);
}

DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(7, "Device not available")
DEFINE_EXCEPTION_WITH_ERROR_CODE(8, "Double fault")
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(9, "Coprocessor segment overrun")
DEFINE_EXCEPTION_WITH_ERROR_CODE(10, "Invalid TSS")
DEFINE_EXCEPTION_WITH_ERROR_CODE(11, "Segment not present")
DEFINE_EXCEPTION_WITH_ERROR_CODE(12, "Stack-segment fault")

DEFINE_ISR_WITH_ERROR_CODE(13)
static void handle_exception13(struct registers* regs) {
    kprint("General protection fault\n");
    crash(regs, SIGSEGV);
}

DEFINE_ISR_WITH_ERROR_CODE(14)
static void handle_exception14(struct registers* regs) {
    void* addr = (void*)read_cr2();
    if (x86_handle_page_fault(regs, addr))
        return;
    crash(regs, SIGSEGV);
}

DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(15, "Unknown")
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(16, "x87 floating-point exception")

ENUMERATE_ISR_STUBS(DEFINE_ISR_WITHOUT_ERROR_CODE)

void idt_init(void) {
#define REGISTER_ISR(num)                                                      \
    set_gate(num, (uintptr_t)isr##num, KERNEL_CS, INTERRUPT_GATE32, 0);

#define REGISTER_EXCEPTION(num)                                                \
    REGISTER_ISR(num);                                                         \
    arch_interrupts_set_handler(num, handle_exception##num);

    REGISTER_EXCEPTION(0);
    REGISTER_EXCEPTION(1);
    REGISTER_EXCEPTION(2);
    REGISTER_EXCEPTION(3);
    REGISTER_EXCEPTION(4);
    REGISTER_EXCEPTION(5);
    REGISTER_EXCEPTION(6);
    REGISTER_EXCEPTION(7);
    REGISTER_EXCEPTION(8);
    REGISTER_EXCEPTION(9);
    REGISTER_EXCEPTION(10);
    REGISTER_EXCEPTION(11);
    REGISTER_EXCEPTION(12);
    REGISTER_EXCEPTION(13);
    REGISTER_EXCEPTION(14);
    REGISTER_EXCEPTION(15);
    REGISTER_EXCEPTION(16);

    ENUMERATE_ISR_STUBS(REGISTER_ISR)

    idt_flush();
}
