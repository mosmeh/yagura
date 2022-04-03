CFLAGS := \
	-std=c11 \
	-m32 \
	-static \
	-nostdlib -ffreestanding \
	-U_FORTIFY_SOURCE \
	-I.. \
	-Wall -Wextra -pedantic \
	-O2 -g

TARGET := kernel

OBJS := \
	bochs_graphics.o \
	boot.o \
	fs/fs.o \
	fs/initrd.o \
	fs/shmfs.o \
	fs/tmpfs.o \
	fs/tree.o \
	fs/vfs.o \
	gdt.o \
	idt.o \
	interrupt.o \
	irq.o \
	kmalloc.o \
	kprintf.o \
	lock.o \
	main.o \
	mem.o \
	pci.o \
	pit.o \
	process.o \
	ps2_mouse.o \
	serial.o \
	syscall/exec.o \
	syscall/file.o \
	syscall/mmap.o \
	syscall/process.o \
	syscall/socket.o \
	syscall/syscall.o \
	system.o \
	unix_socket.o \
 	../common/stdio.o \
 	../common/string.o

DEPS := $(OBJS:.o=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) linker.ld
	$(CC) $(CFLAGS) -Wl,-Tlinker.ld -Wl,--build-id=none -o $@ $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

.S.o:
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
