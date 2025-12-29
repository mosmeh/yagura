CFLAGS += \
	-isystemlibc \
	-isystem.. \
	-isystem../kernel/api
LDFLAGS += -L.

BIN_TARGET_NAMES := \
	cal \
	cat \
	clear \
	cp \
	date \
	dd \
	echo \
	env \
	eyes \
	fib \
	getty \
	grep \
	halt \
	hexdump \
	imgview \
	init \
	init-test \
	kill \
	less \
	ln \
	loadfont \
	ls \
	mandelbrot \
	mkdir \
	mkfifo \
	mknod \
	mount \
	mouse-cursor \
	moused \
	mv \
	play \
	poweroff \
	ps \
	pwd \
	readlink \
	reboot \
	rm \
	rmdir \
	sh \
	sleep \
	stat \
	stty \
	touch \
	uname \
	usertests \
	wc \
	xv6-usertests
OUTDIR := ../base/bin

BIN_TARGETS := $(BIN_TARGET_NAMES:%=$(OUTDIR)/%)
BIN_TARGET_OBJS := $(BIN_TARGET_NAMES:=.o)
BIN_TARGET_DEPS := $(BIN_TARGET_NAMES:=.d)

LIBC_TARGET := libc.a

LIBC_OBJS := \
	../common/libgen.o \
	../common/math.o \
	../common/stdio.o \
	../common/stdlib.o \
	../common/string.o \
	../common/strings.o \
	../common/tree.o \
	../common/ubsan.o \
	libc/asm.o \
	libc/crt0.o \
	libc/dirent.o \
	libc/errno.o \
	libc/fcntl.o \
	libc/panic.o \
	libc/pthread.o \
	libc/sched.o \
	libc/signal.o \
	libc/stdio.o \
	libc/stdlib.o \
	libc/string.o \
	libc/sys/ioctl.o \
	libc/sys/mman.o \
	libc/sys/mount.o \
	libc/sys/poll.o \
	libc/sys/prctl.o \
	libc/sys/random.o \
	libc/sys/select.o \
	libc/sys/socket.o \
	libc/sys/stat.o \
	libc/sys/sysinfo.o \
	libc/sys/time.o \
	libc/sys/times.o \
	libc/sys/uio.o \
	libc/sys/utsname.o \
	libc/sys/wait.o \
	libc/termios.o \
	libc/time.o \
	libc/unistd.o

LIBC_DEPS := $(LIBC_OBJS:.o=.d)

.PHONY: all clean

all: $(BIN_TARGETS)

$(BIN_TARGETS): $(OUTDIR)/% : %.o $(LIBC_TARGET)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lc

$(LIBC_TARGET): $(LIBC_OBJS)
	@echo "[AR] $@"
	@$(AR) rcs $@ $^

.c.o:
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

.S.o:
	@echo "[AS] $<"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) $(BIN_TARGETS) $(BIN_TARGET_OBJS) $(BIN_TARGET_DEPS) $(LIBC_TARGET) $(LIBC_OBJS) $(LIBC_DEPS)

-include $(BIN_TARGET_DEPS)
-include $(LIBC_DEPS)
