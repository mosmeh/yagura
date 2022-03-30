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
	../userland/stdlib.o \
	../userland/syscall.o

OBJS := $(COMMON_OBJS) $(USERLAND_OBJS)

TARGETS := init socket-test

.PHONY: all clean

all: $(TARGETS)

$(TARGETS): % : $(OBJS) %.o
	$(CC) $(CFLAGS) -o ../base/$@ $^

clean:
	rm -f $(TARGETS:%=../base/%) $(OBJS)
