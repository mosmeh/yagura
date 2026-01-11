#!/bin/bash

set -eo pipefail

ARCH="${ARCH:-i386}"
BUILD_DIR="${BUILD_DIR:-build/${ARCH}}"
KERNEL="${KERNEL:-${BUILD_DIR}/kernel.elf}"
INITRD="${INITRD:-${BUILD_DIR}/initrd}"
NUM_CPUS="${NUM_CPUS:-1}"

case "$1" in
    shell) # Serial console
        QEMU_EXTRA_ARGS+=(-display none -vga none)
        CMDLINE+=(console=ttyS0)
        ;;
    text) # Text console
        QEMU_EXTRA_ARGS+=(-display "sdl,gl=off" -vga cirrus)
        CMDLINE+=(console=tty1)
        ;;
    *) # Framebuffer console
        QEMU_EXTRA_ARGS+=(-display "sdl,gl=off,show-cursor=off")
        CMDLINE+=(console=tty1)
        ;;
esac

QEMU_BINARY_PREFIX=''
QEMU_BINARY_SUFFIX=''

if command -v wslpath >/dev/null; then
    PATH=${PATH}:/mnt/c/Windows/System32
    QEMU_INSTALL_DIR=$(reg.exe query 'HKLM\Software\QEMU' /v Install_Dir /t REG_SZ | grep '^    Install_Dir' | sed 's/    / /g' | cut -f4- -d' ')
    QEMU_BINARY_PREFIX="$(wslpath -- "${QEMU_INSTALL_DIR}" | tr -d '\r\n')/"
    QEMU_BINARY_SUFFIX='.exe'
    QEMU_EXTRA_ARGS+=(-accel "whpx,kernel-irqchip=off" -accel tcg)
    KERNEL=$(wslpath -w "${KERNEL}")
    INITRD=$(wslpath -w "${INITRD}")
else
    # NOTE: -cpu max results in "Unexpected VP exit code 4" error when used with WHPX
    QEMU_EXTRA_ARGS+=(-cpu max)

    if [ -r /dev/kvm ] && [ -w /dev/kvm ] &&
        command -v kvm-ok >/dev/null && kvm-ok &>/dev/null; then
        QEMU_EXTRA_ARGS+=(-enable-kvm)
    fi
fi

QEMU_BIN="${QEMU_BINARY_PREFIX}qemu-system-${ARCH}${QEMU_BINARY_SUFFIX}"
"${QEMU_BIN}" \
    -kernel "${KERNEL}" \
    -initrd "${INITRD}" \
    -append "${CMDLINE[*]}" \
    -d guest_errors \
    -device ac97 \
    -chardev stdio,mux=on,id=char0 \
    -serial chardev:char0 \
    -mon char0,mode=readline \
    -m 512M \
    -smp "sockets=1,cores=${NUM_CPUS},threads=1" \
    "${QEMU_EXTRA_ARGS[@]}"
