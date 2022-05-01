CFLAGS += \
	-isystemlib \
	-isystem.. \
	-isystem../common \
	-isystem../kernel/api

TARGET_NAMES := \
	cat \
	clear \
	cp \
	date \
	echo \
	env \
	fib \
	imgview \
	init \
	init-test \
	ls \
	mandelbrot \
	mkdir \
	mouse-cursor \
	pwd \
	reboot \
	run-tests \
	sh \
	sleep \
	touch \
	wc
OUTDIR := ../base/bin

TARGETS := $(TARGET_NAMES:%=$(OUTDIR)/%)
TARGET_OBJS := $(TARGET_NAMES:=.o)
TARGET_DEPS := $(TARGET_NAMES:=.d)

COMMON_OBJS := \
	../common/math.o \
	../common/string.o \
 	../common/stdio.o \
 	../common/stdlib.o \
	lib/crt0.o \
	lib/dirent.o \
	lib/errno.o \
	lib/panic.o \
	lib/stdio.o \
	lib/stdlib.o \
	lib/string.o \
	lib/syscall.o \
	lib/time.o \
	lib/unistd.o

COMMON_DEPS := $(COMMON_OBJS:.o=.d)

.PHONY: all clean

all: $(TARGETS)

$(TARGETS): $(OUTDIR)/% : $(COMMON_OBJS) %.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $^

.c.o:
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) $(TARGETS) $(TARGET_OBJS) $(TARGET_DEPS) $(COMMON_OBJS) $(COMMON_DEPS)

-include $(TARGET_DEPS)
-include $(COMMON_DEPS)
