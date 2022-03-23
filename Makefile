MAKEFLAGS += --jobs=$(shell nproc)

.PHONY: all clean run kernel/kernel tool/mkfs

all: kernel/kernel initrd

kernel/kernel:
	$(MAKE) -C kernel kernel

initrd: tool/mkfs base/*
	'$<' $@ base/*

tool/mkfs:
	$(MAKE) -C tool mkfs

clean:
	$(MAKE) -C kernel $@
	$(MAKE) -C tool $@
	rm -f *.o initrd

run: kernel/kernel initrd
	./run.sh
