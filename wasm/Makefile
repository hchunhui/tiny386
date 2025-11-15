SRCS = \
main.c \
../ini.c \
../i386.c \
../fpu.c \
../i8259.c \
../i8254.c \
../ide.c \
../vga.c \
../i8042.c \
../misc.c \
../fmopl.c \
../adlib.c \
../ne2000.c \
../i8257.c \
../sb16.c \
../pcspk.c \
../pci.c \
../pc.c \
libc/libc.c

.PHONY: all

all:
	clang --target=wasm32 -O3 -nostdlib -fno-builtin -Wl,--no-entry -Wl,--export-all -DNOSDL -I libc -Wl,--allow-undefined -o html/tiny386.wasm ${SRCS}
