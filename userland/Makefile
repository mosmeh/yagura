OUT_DIR := $(BUILD_DIR)/userland

CFLAGS += \
	-isystem$(ROOT)/userland/libc \
	-isystem$(ROOT) \
	-isystem$(ROOT)/kernel/api
LDFLAGS += -L$(OUT_DIR)

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
	false \
	fib \
	fuzz \
	getty \
	grep \
	halt \
	hexdump \
	imgview \
	init \
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
	tests/cwd \
	tests/dup \
	tests/execve \
	tests/framebuffer \
	tests/libgen \
	tests/link \
	tests/malloc \
	tests/mmap \
	tests/mount \
	tests/open \
	tests/pipe \
	tests/random \
	tests/read-write \
	tests/run \
	tests/select \
	tests/string \
	tests/tree \
	tests/uname \
	tests/unix-socket \
	tests/wait \
	tests/xv6-usertests \
	touch \
	true \
	uname \
	wc

BIN_TARGETS := $(addprefix $(USERLAND_BIN_DIR)/,$(BIN_TARGET_NAMES))
BIN_OBJS := $(addprefix $(OUT_DIR)/userland/,$(BIN_TARGET_NAMES:=.o))
BIN_DEPS := $(BIN_OBJS:.o=.d)
BIN_DIRS := $(sort $(dir $(BIN_TARGETS)))

LIBC_TARGET := $(OUT_DIR)/libc.a

LIBC_SRCS := \
	common/libgen.c \
	common/stdio.c \
	common/stdlib.c \
	common/string.c \
	common/strings.c \
	common/tree.c \
	common/ubsan.c \
	userland/libc/crt0.c \
	userland/libc/dirent.c \
	userland/libc/errno.c \
	userland/libc/fcntl.c \
	userland/libc/panic.c \
	userland/libc/pthread.c \
	userland/libc/sched.c \
	userland/libc/signal.c \
	userland/libc/stdio.c \
	userland/libc/stdlib.c \
	userland/libc/string.c \
	userland/libc/sys/ioctl.c \
	userland/libc/sys/mman.c \
	userland/libc/sys/mount.c \
	userland/libc/sys/poll.c \
	userland/libc/sys/prctl.c \
	userland/libc/sys/random.c \
	userland/libc/sys/select.c \
	userland/libc/sys/socket.c \
	userland/libc/sys/stat.c \
	userland/libc/sys/sysinfo.c \
	userland/libc/sys/time.c \
	userland/libc/sys/times.c \
	userland/libc/sys/uio.c \
	userland/libc/sys/utsname.c \
	userland/libc/sys/wait.c \
	userland/libc/termios.c \
	userland/libc/time.c \
	userland/libc/unistd.c

LIBC_X86_SRCS := \
	common/x86/math.c \
	common/x86/string.c

ifeq ($(ARCH), i386)
CFLAGS += \
	-m32 \
	-isystem$(ROOT)/kernel/api/x86

LIBC_SRCS += \
	common/i386/integer.c \
	userland/libc/arch/i386/asm.S \
	userland/libc/arch/i386/tls.c \
	$(LIBC_X86_SRCS)
else ifeq ($(ARCH), x86_64)
CFLAGS += \
	-m64 \
	-isystem$(ROOT)/kernel/api/x86

LIBC_SRCS += \
	userland/libc/arch/x86_64/asm.S \
	userland/libc/arch/x86_64/tls.c \
	$(LIBC_X86_SRCS)
else
$(error Unknown ARCH '$(ARCH)')
endif

LIBC_OBJS := $(addprefix $(OUT_DIR)/,$(LIBC_SRCS:.c=.o))
LIBC_OBJS := $(LIBC_OBJS:.S=.o)
LIBC_DEPS := $(LIBC_OBJS:.o=.d)

OBJ_DIRS := $(sort $(dir $(BIN_OBJS) $(LIBC_OBJS)))

.PHONY: all clean

all: $(BIN_TARGETS)

$(OUT_DIR):
	@mkdir -p $@

$(BIN_DIRS):
	@mkdir -p $@

$(OBJ_DIRS):
	@mkdir -p $@

$(BIN_TARGETS): $(USERLAND_BIN_DIR)/% : $(OUT_DIR)/userland/%.o $(LIBC_TARGET) | $(BIN_DIRS)
	@echo "[LD] $(patsubst $(ROOT)/%,%,$@)"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lc

$(LIBC_TARGET): $(LIBC_OBJS) | $(OUT_DIR)
	@echo "[AR] $(patsubst $(ROOT)/%,%,$@)"
	@$(AR) rcs $@ $^

$(OUT_DIR)/%.o: $(ROOT)/%.c | $(OBJ_DIRS)
	@echo "[CC] $(patsubst $(ROOT)/%,%,$<)"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(OUT_DIR)/%.o: $(ROOT)/%.S | $(OBJ_DIRS)
	@echo "[AS] $(patsubst $(ROOT)/%,%,$<)"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) -r $(OUT_DIR)

-include $(BIN_DEPS)
-include $(LIBC_DEPS)
