CFLAGS := -std=c11 -I.. -Wall -Wextra -pedantic -O2

TARGETS := mkfs

.PHONY: all clean

all: $(TARGETS)

$(TARGETS): % : %.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGETS)
