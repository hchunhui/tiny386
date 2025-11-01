# Tiny386

## Introduction
Tiny386 is a x86 PC emulator written in C99. The highlight of the project is its portability. It now boots Windows 9x/NT on MCU such as ESP32-S3.

The core of the project is a built-from-scratch, simple and stupid i386 cpu emulator. Some features are missing, e.g. debugging, hardware tasking and some permission checks, but it should be able to run most 16/32 bit softwares. To boot modern linux kernel and windows, some 486 and 586 instrutions are added. The cpu emulator is kept in ~6K LOC. There is also an optional x87 fpu emulator.

To assemble a complete PC system, we have ported many peripherals from TinyEMU and QEMU, it now includes:
 - 8259 PIC
 - 8254 PIT
 - 8042 Keyboard Controller
 - CMOS RTC
 - ISA VGA with Bochs VBE
 - IDE Disk Controller
 - NE2000 ISA Network Card
 - 8257 ISA DMA
 - PC Speaker
 - Adlib OPL2
 - SoundBlaster 16

For firmwares, the BIOS/VGABIOS comes from seabios. Tiny386 also supports booting linux kernel directly, without traditional BIOS. The idea comes from JSLinux, and it uses a small stub code called linuxstart.

## Demo
See [here](https://hchunhui.github.io/tiny386)

## License
The cpu emulator and the project as a whole are both licensed under the BSD-3-Clause license.
