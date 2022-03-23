CFLAGS := -std=c11 -I.. -Wall -Wextra -pedantic -O2

.PHONY: all clean

all: mkfs

mkfs: mkfs.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f mkfs
