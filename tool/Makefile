CFLAGS := -std=c11 -I.. -Wall -Wextra -pedantic -O2

TARGETS :=

OBJS := $(TARGETS:=.o)
DEPS := $(TARGETS:=.d)

.PHONY: all clean

all: $(TARGETS)

$(TARGETS): % : %.o
	$(CC) $(CFLAGS) -o $@ $^

.c.o:
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) $(TARGETS) $(OBJS) $(DEPS)

-include $(DEPS)
