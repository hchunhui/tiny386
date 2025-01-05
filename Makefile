CC = gcc
CFLAGS = -O3 -g `sdl-config --cflags`
#CFLAGS = -g `sdl-config --cflags`
LIBS = `sdl-config --libs`
SRCS = main.c i8259.c i8254.c ide.c vga.c i8042.c kvm.c

tiny386: ${SRCS}
	${CC} ${CFLAGS} -o $@ ${SRCS} ${LIBS}
