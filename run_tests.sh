#!/bin/bash

set -e

NCPUS=8

! qemu-system-i386 \
    -kernel kernel/kernel \
    -initrd initrd \
    -append 'panic=poweroff init=/bin/init-test console=ttyS0' \
    -d guest_errors \
    -no-reboot \
    -serial stdio \
    -vga none -display none \
    -smp "cpus=$NCPUS,cores=1,threads=1,sockets=$NCPUS" \
    -m 512M \
    2>&1 | tee >(cat 1>&2) | grep -q PANIC
