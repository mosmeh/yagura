#!/bin/bash

set -eo pipefail

function configure_console() {
    case "$CONSOLE" in
        ''|'fb'|'framebuffer')
            QEMU_EXTRA_ARGS+=(-display "sdl,gl=off,show-cursor=off")
            CMDLINE+=(console=tty0)
            ;;
        serial)
            QEMU_EXTRA_ARGS+=(-display none -vga none)
            CMDLINE+=(console=ttyS0)
            ;;
        text) # VGA text mode
            QEMU_EXTRA_ARGS+=(-display "sdl,gl=off" -vga cirrus)
            CMDLINE+=(console=tty0)
            ;;
        *)
            echo "Unknown CONSOLE: ${CONSOLE}" >&2
            exit 1
            ;;
    esac
}

function configure_acceleration() {
    local qemu_binary_prefix=''
    local qemu_binary_suffix=''

    if command -v wslpath >/dev/null; then
        PATH=${PATH}:/mnt/c/Windows/System32
        local qemu_install_dir
        qemu_install_dir="$(reg.exe query 'HKLM\Software\QEMU' /v Install_Dir /t REG_SZ | grep '^    Install_Dir' | sed 's/    / /g' | cut -f4- -d' ')"
        qemu_binary_prefix="$(wslpath -- "${qemu_install_dir}" | tr -d '\r\n')/"
        qemu_binary_suffix='.exe'
        QEMU_EXTRA_ARGS+=(-accel "whpx,kernel-irqchip=off" -accel tcg)
        KERNEL=$(wslpath -w "${KERNEL}")
        INITRAMFS=$(wslpath -w "${INITRAMFS}")
    else
        # NOTE: -cpu max results in "Unexpected VP exit code 4" error when used with WHPX
        QEMU_EXTRA_ARGS+=(-cpu max)

        if [ -r /dev/kvm ] && [ -w /dev/kvm ] &&
            command -v kvm-ok >/dev/null && kvm-ok &>/dev/null; then
            QEMU_EXTRA_ARGS+=(-enable-kvm)
        fi
    fi

    QEMU_BIN="${qemu_binary_prefix}qemu-system-${ARCH}${qemu_binary_suffix}"
}

function run_qemu() {
    ARCH="${ARCH:-x86_64}"
    BUILD_DIR="${BUILD_DIR:-build/${ARCH}}"
    KERNEL="${KERNEL:-${BUILD_DIR}/kernel.elf}"
    INITRAMFS="${INITRAMFS:-${BUILD_DIR}/initramfs.cpio}"
    MEMORY="${MEMORY:-512M}"
    NUM_CPUS="${NUM_CPUS:-2}"

    configure_console
    configure_acceleration

    "${QEMU_BIN}" \
        -kernel "${KERNEL}" \
        -initrd "${INITRAMFS}" \
        -append "${CMDLINE[*]}" \
        -d guest_errors \
        -m "${MEMORY}" \
        -smp "sockets=1,cores=${NUM_CPUS},threads=1" \
        -chardev stdio,mux=on,id=char0 \
        -serial chardev:char0 \
        -mon char0,mode=readline \
        -device ac97 \
        "${QEMU_EXTRA_ARGS[@]}"
}

case "$1" in
    '')
        run_qemu
        ;;
    test)
        CONSOLE="${CONSOLE:-serial}"
        CMDLINE+=(
            panic=poweroff
            init=/bin/tests/run
        )
        MEMORY="${MEMORY:-256M}"
        QEMU_EXTRA_ARGS+=(-no-reboot)

        run_qemu 2>&1 | tee >(cat 1>&2) | awk '
            /PANIC/ { panic = 1 }
            /ALL TESTS PASSED/ { pass = 1 }
            END {
                if (panic) exit 1
                if (!pass) exit 1
                exit 0
            }'
        ;;
    *)
        echo "Unknown subcommand: $1" >&2
        exit 1
        ;;
esac
