# Tiny386

## Introduction
Tiny386 is an x86 PC emulator written in C99. The highlight of the project is its portability. It now boots Windows 9x/NT on MCU such as ESP32-S3.

The core of the project is a built-from-scratch, simple and stupid i386 cpu emulator. Some features are missing, e.g. debugging, hardware tasking and some permission checks, but it should be able to run most 16/32 bit software. To boot modern linux kernel and windows, some 486 and 586 instrutions are added. The cpu emulator is kept in ~6K LOC. There is also an optional x87 fpu emulator.

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

For firmware, the BIOS/VGABIOS comes from seabios. Tiny386 also supports booting linux kernel directly, without traditional BIOS. The idea comes from JSLinux, and it uses a small stub code called linuxstart.

## Demo
See [here](https://hchunhui.github.io/tiny386)

## Build
Linux (with rawdraw): You need to install `libslirp` `libx11` and `libasound2` first, then type `make`.

Linux (with SDL): You need to install `libslirp` `SDL1.2` (or `sdl12-compat`) first, then type `make USE_SDL=y`.

For other platforms, please refer to `.github/workflows/build.yml`.

Pre-built binaries: [here](https://github.com/hchunhui/tiny386/releases)

## Usage

- Prepare an ini file
```ini
[pc]
; set path to BIOS and VGA BIOS
bios = bios.bin
vga_bios = vgabios.bin

; set memory size and VGA memory size
mem_size = 32M
vga_mem_size = 2M

; fda/fdb for floppy disks (optional)
fda = floppy.img

; hda/hdb/hdc/hdd for hard disks (optional)
; cda/cdb/cdc/cdd for CD-ROM disks (optional)
hda = win95.img
cdb = win95_cd.iso

; "fill_cmos" fixes "MS-DOS compatibility mode" in win9x, but it breaks winNT...
fill_cmos = 1

[display]
width = 720
height = 480

[cpu]
; gen = 3/4/5, for 386/486/586
gen = 3
; fpu = 0/1, to disable/enable x87
fpu = 0
```
- Run
```sh
./tiny386 config.ini
```

For rawdraw and SDL port:
Press "Ctrl + ]" to grab/ungrab the keyboard and mouse. Press "Ctrl + [" to show/hide OSD (On Screen Display). In OSD mode, the floppy/CD-ROM disk can be changed on the fly.

## ESP32 port
Currently the only supported target is the JC3248W535 dev board. The supported ESP-IDF version is v5.2.x.

### Build and Flash
You can find the pre-built flash image `esp/flash_image_JC3248W535.bin` from [here](https://github.com/hchunhui/tiny386/releases).
The pre-built image can be flashed directly to offset 0.

Online flasher for esp chips: https://espressif.github.io/esptool-js

To build and flash manually:
```sh
scripts/build.sh patch_idf  # apply patches to ESP-IDF
make prepare
cd esp
idf.py build
idf.py flash
```

### Configure
All files should be put in a SD card with FAT/exFAT file system. The ini file should be `tiny386.ini` and put in the root directory.
Please refer to `esp/tiny386.ini`.

Alternative usage: `bios.bin` `vgabios.bin` `vmlinux.bin` and `linuxstart.bin` can be put in corresponding flash partition. Other files can be put in the `storage` flash partition. Please refer to `esp/partition.csv`.

### Keyboard/Mouse Input

- Forward over WIFI

`wifikbd` is used to forward keyboard/mouse events to the dev board over WIFI:
```
(ESP32-S3 board: listen on TCP port 9999) <--- WIFI ---> AP <--- WIFI/Wire ---> (PC: ./wifikbd esp_board_addr 9999)
```

- USB hid (WIP)

See [here](https://github.com/hchunhui/tiny386/pull/4).

## Troubleshooting

### "0 bytes of memory" during Windows 95 setup
Use "setup /im" to bypass memory check.

### "protection error" during Windows 95 startup
Use [patcher9x](https://github.com/JHRobotics/patcher9x).

### NE2000 doesn't work
Manually set the IRQ to 9(or 2).

### freeze during Windows NT4/2000/XP startup
Use `fill_cmos = 0` in the config ini file.

## License
The cpu emulator and the project as a whole are both licensed under the BSD-3-Clause license.

SeaBIOS is distributed under the GNU LGPL-3 license.
