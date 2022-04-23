# yagura

[![build](https://github.com/mosmeh/yagura/workflows/build/badge.svg)](https://github.com/mosmeh/yagura/actions)

A Unix-like operating system for x86

## How to run

First, install dependencies:

```sh
# on Ubuntu
sudo apt install gcc-multilib cpio qemu-system-x86
```

Then run the following command to build and run:

```
make run
```

## Installation on bare-metal

You will need additional dependencies:

```sh
# on Ubuntu
sudo apt install grub2 mtools xorriso
```

The following command creates a disk image file called `disk_image`. You can simply copy it onto a disk and boot it.

```sh
make disk_image
```
