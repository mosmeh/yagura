MAKEFLAGS += --jobs=32
SUBDIRS := kernel userland

GIT_HASH := $(shell git describe --always --dirty --exclude '*' 2> /dev/null)

export ARCH ?= i386

export ROOT := $(abspath .)
BUILD_ROOT := $(abspath build)
export BUILD_DIR := $(BUILD_ROOT)/$(ARCH)

export CFLAGS := \
	-std=c11 \
	-static \
	-nostdlib -ffreestanding \
	-fno-omit-frame-pointer \
	-ffile-prefix-map=$(ROOT)/= \
	-U_FORTIFY_SOURCE \
	-Wall -Wextra -pedantic -Wno-gnu-statement-expression-from-macro-expansion \
	-O2 -g \
	-DARCH_$(shell echo $(ARCH) | tr a-z A-Z) \
	$(if $(GIT_HASH),-DYAGURA_VERSION=\"$(GIT_HASH)\") \
	$(EXTRA_CFLAGS)

export LDFLAGS := \
	-Wl,--build-id=none \
	-Wl,-z,noexecstack

BASE_DIR := $(BUILD_DIR)/base
INITRD := $(BUILD_DIR)/initrd

export KERNEL_BIN := $(BUILD_DIR)/kernel.elf
export USERLAND_BIN_DIR := $(BASE_DIR)/bin

.PHONY: all run clean $(SUBDIRS) $(BASE_DIR) disk_image

all: kernel $(INITRD)

$(INITRD): $(BASE_DIR)
	@echo "[CPIO] $(patsubst $(ROOT)/%,%,$@)"
	@find $< -mindepth 1 ! -name '.gitkeep' -printf "%P\n" | sort | cpio -oc -D $< -F $@

$(BASE_DIR): base/* userland
	cp -a base/* $@
	@$(RM) -r $@/root/src
	-git -c advice.detachedHead=false clone . $@/root/src
	@$(RM) -r $@/root/src/.git

$(SUBDIRS):
	$(MAKE) -C $@ all

$(BUILD_DIR)/disk_image: kernel $(INITRD)
	cp -r disk $(BUILD_DIR)/disk
	cp $(KERNEL_BIN) $(INITRD) $(BUILD_DIR)/disk/boot/
	grub-mkrescue -o '$@' $(BUILD_DIR)/disk -d /usr/lib/grub/i386-pc

disk_image: $(BUILD_DIR)/disk_image

clean:
	$(RM) -r $(BUILD_ROOT)

run: kernel $(INITRD)
	./run.sh

shell: kernel $(INITRD)
	./run.sh shell

test: kernel $(INITRD)
	./run_tests.sh
