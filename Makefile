MAKEFLAGS += --jobs=$(shell nproc)
SUBDIRS := kernel userland tool

.PHONY: all run clean $(SUBDIRS) base

all: kernel initrd

initrd: base
	find $< -mindepth 1 ! -name '.gitkeep' -printf "%P\n" | cpio -oc -D $< -F $@

base: $@/* userland
	$(RM) -r $@/root/src
	-git clone . $@/root/src
	$(RM) -r $@/root/src/.git

$(SUBDIRS):
	$(MAKE) -C $@ all

clean:
	for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@; done
	$(RM) -r base/root/src
	$(RM) initrd

run: kernel initrd
	./run.sh
