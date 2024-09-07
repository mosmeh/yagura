MAKEFLAGS += --jobs=32
SUBDIRS := kernel userland

GIT_HASH := $(shell git describe --always --dirty --exclude '*' 2> /dev/null)

export CFLAGS := \
	-std=c11 \
	-m32 \
	-static \
	-nostdlib -ffreestanding \
	-fno-omit-frame-pointer \
	-U_FORTIFY_SOURCE \
	-Wall -Wextra -pedantic \
	-O2 -g \
	$(if $(GIT_HASH),-DYAGURA_VERSION=\"$(GIT_HASH)\") \
	$(EXTRA_CFLAGS)

export LDFLAGS := \
	-Wl,--build-id=none \
	-Wl,-z,noexecstack

.PHONY: all run clean $(SUBDIRS) base

all: kernel initrd

initrd: base
	find $< -mindepth 1 ! -name '.gitkeep' -printf "%P\n" | sort | cpio -oc -D $< -F $@

base: $@/* userland
	$(RM) -r $@/root/src
	-git -c advice.detachedHead=false clone . $@/root/src
	$(RM) -r $@/root/src/.git

$(SUBDIRS):
	$(MAKE) -C $@ all

disk_image: kernel initrd
	cp kernel/kernel initrd disk/boot
	grub-mkrescue -o '$@' disk -d /usr/lib/grub/i386-pc

clean:
	for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@; done
	$(RM) -r base/root/src
	$(RM) initrd disk_image disk/boot/kernel disk/boot/initrd

run: kernel initrd
	./run.sh

shell: kernel initrd
	./run.sh shell

test: kernel initrd
	./run_tests.sh
