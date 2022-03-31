CFLAGS := \
	-std=c11 \
	-m32 \
	-static \
	-nostdlib -ffreestanding \
	-I.. \
	-Wall -Wextra -pedantic \
	-O2 -g

COMMON_OBJS := ../common/string.o

USERLAND_OBJS := \
	stdlib.o \
	syscall.o

OBJS := $(COMMON_OBJS) $(USERLAND_OBJS)

TARGET_NAMES := init socket-test fs-test

OUTDIR := ../base
TARGETS := $(TARGET_NAMES:%=$(OUTDIR)/%)

.PHONY: all clean

all: $(TARGETS)

$(TARGETS): $(OUTDIR)/% : $(OBJS) %.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET_NAMES:%=%.o) $(TARGETS) $(OBJS)
