CFLAGS := \
	-std=c11 \
	-m32 \
	-static \
	-nostdlib -ffreestanding \
	-I.. \
	-Wall -Wextra -pedantic \
	-O2 -g

KERNEL_OBJS := \
	boot.o \
	interrupt.o \
	main.o \
	system.o \
	gdt.o \
	idt.o \
	irq.o \
	pit.o \
	mem.o \
	kmalloc.o \
	process.o \
	syscall.o \
	lock.o \
	serial.o \
	ps2_mouse.o \
	pci.o \
	kprintf.o \
	bochs_graphics.o \
	fs/fs.o \
	fs/initrd.o

COMMON_OBJS := ../common/string.o

USERLAND_OBJS := \
	../userland/syscall.o \
	../userland/stdlib.o

OBJS := $(KERNEL_OBJS) $(COMMON_OBJS) $(USERLAND_OBJS)

.PHONY: all clean

all: kernel

kernel: $(OBJS) linker.ld
	$(CC) $(CFLAGS) -Wl,-Tlinker.ld -Wl,--build-id=none -o '$@' $(OBJS)

.S.o:
	$(CC) $(CFLAGS) -c -o '$@' '$<'

clean:
	rm -f kernel $(OBJS)
