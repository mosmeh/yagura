#!/bin/bash

set -eo pipefail

ARCH="${ARCH:-i386}"
BUILD_DIR="${BUILD_DIR:-build/${ARCH}}"
KERNEL="${KERNEL:-${BUILD_DIR}/kernel.elf}"
INITRD="${INITRD:-${BUILD_DIR}/initrd.img}"

"qemu-system-${ARCH}" \
    -kernel "${KERNEL}" \
    -initrd "${INITRD}" \
    -append 'panic=poweroff init=/bin/tests/run console=ttyS0' \
    -d guest_errors \
    -no-reboot \
    -cpu max \
    -serial stdio \
    -vga none -display none \
    -m 256M \
    2>&1 | tee >(cat 1>&2) | awk '
    /PANIC/ { panic = 1 }
    /ALL TESTS PASSED/ { pass = 1 }
    END {
        if (panic) exit 1
        if (!pass) exit 1
        exit 0
    }'
