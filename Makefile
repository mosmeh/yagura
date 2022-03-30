MAKEFLAGS += --jobs=$(shell nproc)
SUBDIRS := kernel userland tool

.PHONY: all run clean $(SUBDIRS)

all: kernel initrd

initrd: tool base/* userland
	tool/mkfs $@ base/*

$(SUBDIRS):
	$(MAKE) -C $@ all

clean:
	for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean; done
	rm -f initrd

run: kernel initrd
	./run.sh
