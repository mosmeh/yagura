OUT_DIR := $(BUILD_DIR)/kernel

CFLAGS += \
	-ffreestanding \
	-isystem$(ROOT)

LINKER_SCRIPT := $(OUT_DIR)/kernel.lds
LDFLAGS += -Wl,-T$(LINKER_SCRIPT)

SRCS := \
	common/libgen.c \
	common/stdio.c \
	common/stdlib.c \
	common/string.c \
	common/tree.c \
	common/ubsan.c \
	kernel/cmdline.c \
	kernel/console/console.c \
	kernel/console/font.c \
	kernel/console/key_map.c \
	kernel/console/screen/fb.c \
	kernel/console/screen/screen.c \
	kernel/console/screen/vga_text.c \
	kernel/console/serial_console.c \
	kernel/console/system_console.c \
	kernel/console/tty.c \
	kernel/console/virtual_console.c \
	kernel/console/vt.c \
	kernel/containers/vec.c \
	kernel/cpu.c \
	kernel/device/device.c \
	kernel/device/pseudo.c \
	kernel/drivers/ac97.c \
	kernel/drivers/acpi.c \
	kernel/drivers/drivers.c \
	kernel/drivers/graphics/bochs.c \
	kernel/drivers/graphics/boot.c \
	kernel/drivers/graphics/fb.c \
	kernel/drivers/hid/keyboard.c \
	kernel/drivers/hid/mouse.c \
	kernel/drivers/hid/ps2.c \
	kernel/drivers/pci.c \
	kernel/drivers/serial.c \
	kernel/drivers/virtio/virtio_blk.c \
	kernel/drivers/virtio/virtio.c \
	kernel/exec/elf.c \
	kernel/exec/exec.c \
	kernel/exec/shebang.c \
	kernel/fs/file.c \
	kernel/fs/filemap.c \
	kernel/fs/fs.c \
	kernel/fs/initrd.c \
	kernel/fs/path.c \
	kernel/fs/pipe.c \
	kernel/fs/proc/pid.c \
	kernel/fs/proc/proc.c \
	kernel/fs/proc/root.c \
	kernel/fs/tmpfs.c \
	kernel/fs/vfs.c \
	kernel/kmsg.c \
	kernel/ksyms.c \
	kernel/lock.c \
	kernel/main.c \
	kernel/memory/kmalloc.c \
	kernel/memory/memory.c \
	kernel/memory/page_table.c \
	kernel/memory/phys.c \
	kernel/memory/safe_string.c \
	kernel/memory/slab.c \
	kernel/memory/vm_obj.c \
	kernel/memory/vm_region.c \
	kernel/memory/vm.c \
	kernel/random.c \
	kernel/sched.c \
	kernel/socket.c \
	kernel/syscall/dir.c \
	kernel/syscall/file_ctrl.c \
	kernel/syscall/file_io.c \
	kernel/syscall/fs.c \
	kernel/syscall/mmap.c \
	kernel/syscall/path.c \
	kernel/syscall/select.c \
	kernel/syscall/signal.c \
	kernel/syscall/socket.c \
	kernel/syscall/stat.c \
	kernel/syscall/syscall.c \
	kernel/syscall/system.c \
	kernel/syscall/task.c \
	kernel/syscall/time.c \
	kernel/system.c \
	kernel/task/fs.c \
	kernel/task/signal.c \
	kernel/task/task.c \
	kernel/time.c

X86_SRCS := \
	common/x86/string.c \
	kernel/arch/x86/boot/multiboot.S \
	kernel/arch/x86/boot/start.c \
	kernel/arch/x86/cpu.c \
	kernel/arch/x86/gdt.c \
	kernel/arch/x86/interrupts/apic.c \
	kernel/arch/x86/interrupts/i8259.c \
	kernel/arch/x86/interrupts/idt.c \
	kernel/arch/x86/interrupts/pit.c \
	kernel/arch/x86/memory/page_fault.c \
	kernel/arch/x86/memory/page_table.c \
	kernel/arch/x86/memory/safe_string.c \
	kernel/arch/x86/power.c \
	kernel/arch/x86/random.c \
	kernel/arch/x86/rtc.c \
	kernel/arch/x86/smp.c \
	kernel/arch/x86/syscall/ia32.c \
	kernel/arch/x86/syscall/syscall.c \
	kernel/arch/x86/task/context.c \
	kernel/arch/x86/task/signal.c \
	kernel/arch/x86/task/tls.c

ifeq ($(ARCH), i386)
LINKER_SCRIPT_SRC := $(ROOT)/kernel/arch/x86/kernel.lds.S

CFLAGS += \
	-m32 \
	-isystem$(ROOT)/kernel/api/x86 \
	-isystem$(ROOT)/kernel/arch/i386/include \
	-isystem$(ROOT)/kernel/arch/x86/include

SRCS += \
	common/i386/integer.c \
	kernel/arch/i386/boot.S \
	kernel/arch/i386/context.c \
	kernel/arch/i386/interrupts.S \
	$(X86_SRCS)
else
$(error Unknown ARCH '$(ARCH)')
endif

OBJS := $(addprefix $(OUT_DIR)/,$(SRCS:.c=.o))
OBJS := $(OBJS:.S=.o)
DEPS := $(OBJS:.o=.d)
OBJ_DIRS := $(sort $(dir $(OBJS)))

.PHONY: all clean

all: $(KERNEL_BIN)

$(OUT_DIR):
	@mkdir -p $@

$(OUT_DIR)/stage0.ksyms.o: ksyms.S | $(OUT_DIR)
	@echo "[AS] $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

# stage1 is built with an empty symbol table
$(OUT_DIR)/stage1: $(OUT_DIR)/stage0.ksyms.o $(OBJS) $(LINKER_SCRIPT)
	@echo "[LD] $(patsubst $(ROOT)/%,%,$@)"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $<

# stage2 will have a correct list of symbols, but the addresses will be wrong
$(OUT_DIR)/stage2: $(OUT_DIR)/stage1.ksyms.o $(OBJS) $(LINKER_SCRIPT)
	@echo "[LD] $(patsubst $(ROOT)/%,%,$@)"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $<

# stage3 will have correct addresses
$(KERNEL_BIN): $(OUT_DIR)/stage2.ksyms.o $(OBJS) $(LINKER_SCRIPT)
	@echo "[LD] $(patsubst $(ROOT)/%,%,$@)"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $<

$(OUT_DIR)/%.ksyms.o: ksyms.S $(OUT_DIR)/%.ksyms
	@echo "[AS] $<"
	@$(CC) $(CFLAGS) -DKSYMS='"$(OUT_DIR)/$*.ksyms"' -c -o $@ $<

%.ksyms: % | $(OUT_DIR)
	@echo "[KSYMS] $(patsubst $(ROOT)/%,%,$<)"
	@nm -n $< > $@

$(OBJ_DIRS):
	@mkdir -p $@

$(OUT_DIR)/%.o: $(ROOT)/%.c | $(OBJ_DIRS)
	@echo "[CC] $(patsubst $(ROOT)/%,%,$<)"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(OUT_DIR)/%.o: $(ROOT)/%.S | $(OBJ_DIRS)
	@echo "[AS] $(patsubst $(ROOT)/%,%,$<)"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(LINKER_SCRIPT): $(LINKER_SCRIPT_SRC) | $(OUT_DIR)
	@echo "[CPP] $(patsubst $(ROOT)/%,%,$<)"
	@$(CC) $(CFLAGS) -E -P -x assembler-with-cpp -o $@ $<

clean:
	$(RM) -r $(OUT_DIR)

-include $(DEPS)
