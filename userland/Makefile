CFLAGS += \
	-isystemlib \
	-isystem.. \
	-isystem../common \
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

LIB_TARGET := libc.a

LIB_OBJS := \
	../common/math.o \
	../common/string.o \
	../common/strings.o \
 	../common/stdio.o \
 	../common/stdlib.o \
	lib/asm.o \
	lib/crt0.o \
	lib/dirent.o \
	lib/errno.o \
	lib/fcntl.o \
	lib/panic.o \
	lib/pthread.o \
	lib/sched.o \
	lib/signal.o \
	lib/stdio.o \
	lib/stdlib.o \
	lib/string.o \
	lib/sys/ioctl.o \
	lib/sys/mman.o \
	lib/sys/mount.o \
	lib/sys/poll.o \
	lib/sys/prctl.o \
	lib/sys/select.o \
	lib/sys/socket.o \
	lib/sys/stat.o \
	lib/sys/sysinfo.o \
	lib/sys/time.o \
	lib/sys/times.o \
	lib/sys/uio.o \
	lib/sys/utsname.o \
	lib/sys/wait.o \
	lib/termios.o \
	lib/time.o \
	lib/unistd.o

LIB_DEPS := $(LIB_OBJS:.o=.d)

.PHONY: all clean

all: $(BIN_TARGETS)

$(BIN_TARGETS): $(OUTDIR)/% : %.o $(LIB_TARGET)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lc

$(LIB_TARGET): $(LIB_OBJS)
	@echo "[AR] $@"
	@$(AR) rcs $@ $^

.c.o:
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

.S.o:
	@echo "[AS] $<"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) $(BIN_TARGETS) $(BIN_TARGET_OBJS) $(BIN_TARGET_DEPS) $(LIB_TARGET) $(LIB_OBJS) $(LIB_DEPS)

-include $(BIN_TARGET_DEPS)
-include $(LIB_DEPS)
