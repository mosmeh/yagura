CFLAGS := \
	-std=c11 \
	-m32 \
	-static \
	-nostdlib -ffreestanding \
	-I.. \
	-Wall -Wextra -pedantic \
	-O2 -g

KERNEL_OBJS := \
	bochs_graphics.o \
	boot.o \
	fs/fs.o \
	fs/initrd.o \
	fs/tmpfs.o \
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
	panic.o \
	pci.o \
	pit.o \
	process.o \
	ps2_mouse.o \
	serial.o \
	syscall/file.o \
	syscall/mmap.o \
	syscall/process.o \
	syscall/socket.o \
	syscall/syscall.o \
	system.o \
	unix_socket.o

COMMON_OBJS := ../common/string.o

OBJS := $(KERNEL_OBJS) $(COMMON_OBJS)

.PHONY: all clean

all: kernel

kernel: $(OBJS) linker.ld
	$(CC) $(CFLAGS) -Wl,-Tlinker.ld -Wl,--build-id=none -o '$@' $(OBJS)

.S.o:
	$(CC) $(CFLAGS) -c -o '$@' '$<'

clean:
	rm -f kernel $(OBJS)
