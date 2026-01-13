# yagura

[![build](https://github.com/mosmeh/yagura/workflows/build/badge.svg)](https://github.com/mosmeh/yagura/actions)

A Unix-like operating system for x86

![](imgs/screenshot.png)

See [Gallery](docs/gallery.md) for more screenshots.

## How to run

First, install dependencies:

```sh
# on Ubuntu
sudo apt install gcc-multilib cpio qemu-system-x86
```

Then run the following command to build and run:

```sh
make run
```

The following commands start the system with different options:

```sh
make serial # run with a serial console
make text # run in VGA text mode
make test # run self-test
```

## Installation on bare-metal

You will need additional dependencies:

```sh
# on Ubuntu
sudo apt install grub2 mtools xorriso
```

The following command creates a disk image file at `build/i386/disk_image`. You can simply copy it onto a disk and boot it.

```sh
make disk_image
```

## Inspirations and learning resources

- [xv6](https://github.com/mit-pdos/xv6-public)
- [SerenityOS](https://github.com/SerenityOS/serenity)
- [ToaruOS](https://github.com/klange/toaruos)
- [JamesM's kernel development tutorials](http://www.jamesmolloy.co.uk/tutorial_html/)
- [OSDev Wiki](https://wiki.osdev.org/)
