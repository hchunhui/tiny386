CC = gcc
CFLAGS = -O3 -g `sdl-config --cflags`
#CFLAGS = -g `sdl-config --cflags`
LIBS = `sdl-config --libs` -lm
SRCS = main.c i386.c i8259.c i8254.c ide.c vga.c i8042.c misc.c kvm.c fmopl.c adlib.c

tiny386: ${SRCS}
	${CC} ${CFLAGS} -o $@ ${SRCS} ${LIBS}
