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

CFLAGS = -DI386_ENABLE_MMX -DI386_ENABLE_SSE -DI386_ENABLE_SSE2

.PHONY: all

all:
	clang --target=wasm32 -O3 -nostdlib -fno-builtin -ffunction-sections -fdata-sections -fvisibility=default -I libc ${CFLAGS} -Wl,--gc-sections -Wl,--export-dynamic -Wl,--no-entry -Wl,--strip-all -Wl,--allow-undefined -o html/tiny386.wasm ${SRCS}
