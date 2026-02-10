#include <kernel/api/i386/asm/unistd.h>
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
#ifdef ARCH_X86_64
    uint32_t base_hi2;
    uint32_t reserved3;
#endif
};

struct idtr {
    uint16_t limit;
#ifdef ARCH_I386
    uint32_t base;
#endif
#ifdef ARCH_X86_64
    uint64_t base;
#endif
} __attribute__((packed));

#define NUM_IDT_ENTRIES 256

static struct idt_gate idt[NUM_IDT_ENTRIES];
static interrupt_handler_fn interrupt_handlers[NUM_IDT_ENTRIES];

void arch_interrupts_set_handler(uint8_t num, interrupt_handler_fn handler) {
    interrupt_handlers[num] = handler;
}

void isr_handler(struct registers* regs) {
    unsigned long interrupt_num = regs->interrupt_num;
    ASSERT(interrupt_num < NUM_IDT_ENTRIES);
    ASSERT(!arch_interrupts_enabled());

    if (interrupt_num >= IRQ(0) && interrupt_num != SYSCALL_VECTOR) {
        unsigned long irq = interrupt_num - IRQ(0);
        if (irq < NUM_IRQS)
            i8259_eoi(irq);

        if (interrupt_num != SPURIOUS_VECTOR)
            lapic_eoi();
    }

    cpu_process_messages();

    interrupt_handler_fn handler = interrupt_handlers[interrupt_num];
    if (handler)
        handler(regs);
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
#ifdef ARCH_X86_64
        .base_hi2 = (base >> 32) & 0xffffffff,
#endif
    };
}

void idt_set_gate_user_callable(uint8_t index) { idt[index].dpl = 3; }

static void load_idt(const struct idtr* idtr) {
    __asm__ volatile("lidt %0" ::"m"(*idtr) : "memory");
}

void idt_invalidate(void) {
    static const struct idtr idtr = {0};
    load_idt(&idtr);
}

void idt_flush(void) {
    static const struct idtr idtr = {
        .limit = sizeof(idt) - 1,
        .base = (uintptr_t)idt,
    };
    load_idt(&idtr);
}

static _Noreturn void crash(const struct registers* regs, int signum) {
    arch_dump_registers(regs);
    dump_stack_trace(regs->ip, regs->bp);

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

#define DEFINE_EXCEPTION(num, msg, signum)                                     \
    static void handle_exception##num(struct registers* regs) {                \
        kprint("Exception: " msg "\n");                                        \
        crash(regs, signum);                                                   \
    }

#define DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(num, msg, signum)                  \
    DEFINE_ISR_WITHOUT_ERROR_CODE(num)                                         \
    DEFINE_EXCEPTION(num, msg, signum)

#define DEFINE_EXCEPTION_WITH_ERROR_CODE(num, msg, signum)                     \
    DEFINE_ISR_WITH_ERROR_CODE(num)                                            \
    DEFINE_EXCEPTION(num, msg, signum)

DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(0, "Divide-by-zero error", SIGFPE)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(1, "Debug", SIGTRAP)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(2, "Non-maskable interrupt", SIGSEGV)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(3, "Breakpoint", SIGSEGV)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(4, "Overflow", SIGSEGV)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(5, "Bound range exceeded", SIGSEGV)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(6, "Invalid opcode", SIGILL)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(7, "Device not available", SIGSEGV)
DEFINE_EXCEPTION_WITH_ERROR_CODE(8, "Double fault", SIGSEGV)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(9, "Coprocessor segment overrun", SIGFPE)
DEFINE_EXCEPTION_WITH_ERROR_CODE(10, "Invalid TSS", SIGSEGV)
DEFINE_EXCEPTION_WITH_ERROR_CODE(11, "Segment not present", SIGBUS)
DEFINE_EXCEPTION_WITH_ERROR_CODE(12, "Stack-segment fault", SIGBUS)
DEFINE_EXCEPTION_WITH_ERROR_CODE(13, "General protection fault", SIGSEGV)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(16, "x87 floating-point exception", SIGFPE)
DEFINE_EXCEPTION_WITH_ERROR_CODE(17, "Alignment check", SIGBUS)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(18, "Machine check", SIGBUS)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(19, "SIMD floating-point exception", SIGFPE)
DEFINE_EXCEPTION_WITHOUT_ERROR_CODE(20, "Virtualization exception", SIGSEGV)
DEFINE_EXCEPTION_WITH_ERROR_CODE(21, "Control protection exception", SIGSEGV)

DEFINE_ISR_WITH_ERROR_CODE(14) // Page fault
static void handle_exception14(struct registers* regs) {
    void* addr = (void*)read_cr2();
    if (x86_handle_page_fault(regs, addr))
        return;
    crash(regs, SIGSEGV);
}

DEFINE_ISR_WITHOUT_ERROR_CODE(15) // Spurious interrupt

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
    REGISTER_ISR(15);
    REGISTER_EXCEPTION(16);
    REGISTER_EXCEPTION(17);
    REGISTER_EXCEPTION(18);
    REGISTER_EXCEPTION(19);
    REGISTER_EXCEPTION(20);
    REGISTER_EXCEPTION(21);

    ENUMERATE_ISR_STUBS(REGISTER_ISR)

    idt_flush();
}
