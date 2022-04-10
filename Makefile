MAKEFLAGS += --jobs=$(shell nproc)
SUBDIRS := kernel userland tool

.PHONY: all run clean $(SUBDIRS)

all: kernel initrd

initrd: base
	find $< -mindepth 1 ! -name '.gitkeep' -printf "%P\n" | cpio -oc -D $< -F $@

base: $@/* userland
	$(RM) -r $@/src
	-git clone . $@/src
	$(RM) -r $@/src/.git

$(SUBDIRS):
	$(MAKE) -C $@ all

clean:
	for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@; done
	$(RM) -r base/src
	$(RM) initrd

run: kernel initrd
	./run.sh
