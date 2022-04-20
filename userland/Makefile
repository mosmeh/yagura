CFLAGS := \
	-std=c11 \
	-m32 \
	-static \
	-nostdlib -ffreestanding \
	-U_FORTIFY_SOURCE \
	-I.. \
	-Wall -Wextra -pedantic \
	-O2 -g

TARGET_NAMES := \
	cat \
	clear \
	cp \
	echo \
	env \
	fs-test \
	imgview \
	init \
	ls \
	mandelbrot \
	mkdir \
	mouse_cursor \
	sh \
	sleep \
	socket-test \
	touch
OUTDIR := ../base/bin

TARGETS := $(TARGET_NAMES:%=$(OUTDIR)/%)
TARGET_OBJS := $(TARGET_NAMES:=.o)
TARGET_DEPS := $(TARGET_NAMES:=.d)

COMMON_OBJS := \
	../common/math.o \
 	../common/stdio.o \
 	../common/stdlib.o \
	../common/string.o \
	stdlib.o \
	syscall.o

COMMON_DEPS := $(COMMON_OBJS:.o=.d)

.PHONY: all clean

all: $(TARGETS)

$(TARGETS): $(OUTDIR)/% : $(COMMON_OBJS) %.o
	$(CC) $(CFLAGS) -o $@ $^

.c.o:
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) $(TARGETS) $(TARGET_OBJS) $(TARGET_DEPS) $(COMMON_OBJS) $(COMMON_DEPS)

-include $(TARGET_DEPS)
-include $(COMMON_DEPS)
