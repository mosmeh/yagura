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
	string.o \
	lock.o \
	serial.o \
	kprintf.o \
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
