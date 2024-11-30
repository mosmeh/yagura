#!/bin/bash

set -eo pipefail

KERNEL='kernel/kernel'
INITRD='initrd'
CMDLINE=()
#CMDLINE=(ni_syscall_log syscall_log)
#CMDLINE=(ni_syscall_log)
NUM_CPUS=1

case "$1" in
    shell) # Serial console
        QEMU_DISPLAY_ARGS=(-display none -vga none)
        CMDLINE+=(console=ttyS0)
        ;;
    text) # Text console
        QEMU_DISPLAY_ARGS=(-display "sdl,gl=off" -vga cirrus)
        CMDLINE+=(console=tty1)
        ;;
    *) # Framebuffer console
        QEMU_DISPLAY_ARGS=(-display "sdl,gl=off,show-cursor=off")
        CMDLINE+=(console=tty1)
        ;;
esac

QEMU_BINARY_PREFIX=''
QEMU_BINARY_SUFFIX=''
QEMU_VIRT_TECH_ARGS=()

if [ -r /dev/kvm ] && [ -w /dev/kvm ] &&
    command -v kvm-ok >/dev/null && kvm-ok &>/dev/null; then
    QEMU_VIRT_TECH_ARGS=(-enable-kvm)
fi

if command -v wslpath >/dev/null; then
    PATH=${PATH}:/mnt/c/Windows/System32
    QEMU_INSTALL_DIR=$(reg.exe query 'HKLM\Software\QEMU' /v Install_Dir /t REG_SZ | grep '^    Install_Dir' | sed 's/    / /g' | cut -f4- -d' ')
    QEMU_BINARY_PREFIX="$(wslpath -- "${QEMU_INSTALL_DIR}" | tr -d '\r\n')/"
    QEMU_BINARY_SUFFIX='.exe'
    QEMU_VIRT_TECH_ARGS=(-accel "whpx,kernel-irqchip=off" -accel tcg)
    KERNEL=$(wslpath -w "${KERNEL}")
    INITRD=$(wslpath -w "${INITRD}")
fi

QEMU_BIN="${QEMU_BINARY_PREFIX}qemu-system-i386${QEMU_BINARY_SUFFIX}"
"${QEMU_BIN}" \
    -kernel "${KERNEL}" \
    -initrd "${INITRD}" \
    -append "${CMDLINE[*]}" \
    -d guest_errors \
    "${QEMU_DISPLAY_ARGS[@]}" \
    -chardev stdio,mux=on,id=char0 \
    -serial chardev:char0 \
    -mon char0,mode=readline \
    -no-reboot \
    -cpu max \
    -m 512M \
    -smp "sockets=1,cores=${NUM_CPUS},threads=1" \
    -drive id=drive,file=img,format=raw,if=none \
    -device virtio-blk,drive=drive \
    "${QEMU_VIRT_TECH_ARGS[@]}"
