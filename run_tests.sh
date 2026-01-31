#!/bin/bash

set -e

ARCH="${ARCH:-i386}"
BUILD_DIR="${BUILD_DIR:-build/${ARCH}}"
KERNEL="${KERNEL:-${BUILD_DIR}/kernel.elf}"
INITRD="${INITRD:-${BUILD_DIR}/initrd.img}"

! "qemu-system-${ARCH}" \
    -kernel "${KERNEL}" \
    -initrd "${INITRD}" \
    -append 'panic=poweroff init=/bin/tests/run console=ttyS0' \
    -d guest_errors \
    -no-reboot \
    -cpu max \
    -serial stdio \
    -vga none -display none \
    -m 256M \
    2>&1 | tee >(cat 1>&2) | grep -q PANIC
