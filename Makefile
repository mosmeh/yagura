SUBDIRS := kernel userland

GIT_HASH := $(shell git describe --always --dirty --exclude '*' 2> /dev/null)

ifeq ($(CROSS_COMPILE),)
export CC ?= cc
export AR ?= ar
export OBJCOPY ?= objcopy
export NM ?= nm
else
export CC := $(CROSS_COMPILE)gcc
export AR := $(CROSS_COMPILE)ar
export OBJCOPY := $(CROSS_COMPILE)objcopy
export NM := $(CROSS_COMPILE)nm
endif

export ARCH ?= x86_64

export ROOT := $(abspath .)
BUILD_ROOT := $(abspath build)
export BUILD_DIR := $(BUILD_ROOT)/$(ARCH)

export CFLAGS := \
	-std=c11 \
	-nostdlib -nostdinc \
	-fno-omit-frame-pointer \
	-ffile-prefix-map=$(ROOT)/= \
	-ftrivial-auto-var-init=pattern \
	-Wall -Wextra -pedantic -Wshadow \
	-O2 -g \
	-DARCH_$(shell echo $(ARCH) | tr a-z A-Z) \
	$(if $(GIT_HASH),-DYAGURA_VERSION=\"$(GIT_HASH)\") \
	$(EXTRA_CFLAGS)

export LDFLAGS := \
	-static \
	-nostdlib \
	-Wl,--build-id=none \
	-Wl,-z,noexecstack

BASE_DIR := $(BUILD_DIR)/base

export KERNEL := $(BUILD_DIR)/kernel.elf
export INITRAMFS := $(BUILD_DIR)/initramfs.cpio
export USERLAND_BIN_DIR := $(BASE_DIR)/bin

.PHONY: all $(BASE_DIR) $(SUBDIRS) disk_image clean run test

all: kernel $(INITRAMFS)

$(INITRAMFS): $(BASE_DIR)
	@echo "[CPIO] $(patsubst $(ROOT)/%,%,$@)"
	@cd $(BASE_DIR) && find . ! -name '.gitkeep' | cpio -o -H newc > $@

$(BASE_DIR): base/* userland
	cp -a base/* $@
	@$(RM) -r $@/root/src
	-git -c advice.detachedHead=false clone . $@/root/src
	@$(RM) -r $@/root/src/.git

$(SUBDIRS):
	$(MAKE) -C $@ all

$(BUILD_DIR)/disk_image: kernel $(INITRAMFS)
	cp -r disk $(BUILD_DIR)/disk
	cp $(KERNEL) $(INITRAMFS) $(BUILD_DIR)/disk/boot/
	grub-mkrescue -o '$@' $(BUILD_DIR)/disk -d /usr/lib/grub/i386-pc

disk_image: $(BUILD_DIR)/disk_image

clean:
	$(RM) -r $(BUILD_ROOT)

run: kernel $(INITRAMFS)
	./run.sh

test: kernel $(INITRAMFS)
	./run_tests.sh
