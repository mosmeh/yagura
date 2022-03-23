#!/bin/bash

set -e

KERNEL='kernel/kernel'
INITRD='initrd'

unset QEMU_BINARY_PREFIX
unset QEMU_BINARY_SUFFIX
unset QEMU_VIRT_TECH_ARGS

if command -v wslpath >/dev/null; then
	PATH=${PATH}:/mnt/c/Windows/System32
	QEMU_INSTALL_DIR=$(reg.exe query 'HKLM\Software\QEMU' /v Install_Dir /t REG_SZ | grep '^    Install_Dir' | sed 's/    / /g' | cut -f4- -d' ')
	QEMU_BINARY_PREFIX="$(wslpath -- "${QEMU_INSTALL_DIR}" | tr -d '\r\n')/"
	QEMU_BINARY_SUFFIX='.exe'
	QEMU_VIRT_TECH_ARGS=(-accel whpx -accel tcg)
	KERNEL=$(wslpath -w "${KERNEL}")
	INITRD=$(wslpath -w "${INITRD}")
fi

QEMU_BIN="${QEMU_BINARY_PREFIX}qemu-system-i386${QEMU_BINARY_SUFFIX}"
"${QEMU_BIN}" -kernel "${KERNEL}" \
	-initrd "${INITRD}" \
	-d guest_errors \
	-nographic -no-reboot \
	-serial stdio -serial stdio -serial stdio -serial stdio \
	-chardev stdio,mux=on,id=char0 -mon chardev=char0,mode=readline -s \
	"${QEMU_VIRT_TECH_ARGS[@]}"
