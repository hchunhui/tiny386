CC = gcc
CFLAGS = -O3 -g `sdl-config --cflags`
#CFLAGS = -g `sdl-config --cflags`
LIBS = `sdl-config --libs` -lm
SRCS = main.c ini.c i386.c fpu.c i8259.c i8254.c ide.c vga.c i8042.c misc.c kvm.c fmopl.c adlib.c ne2000.c i8257.c sb16.c
SRCS += pci.c

# slirp
SRCS += \
slirp/bootp.c \
slirp/cksum.c \
slirp/if.c \
slirp/ip_icmp.c \
slirp/ip_input.c \
slirp/ip_output.c \
slirp/mbuf.c \
slirp/misc.c \
slirp/sbuf.c \
slirp/slirp.c \
slirp/socket.c \
slirp/tcp_input.c \
slirp/tcp_output.c \
slirp/tcp_subr.c \
slirp/tcp_timer.c \
slirp/cutils.c \
slirp/udp.c

tiny386: ${SRCS}
	${CC} ${CFLAGS} -o $@ ${SRCS} ${LIBS}

tiny386_nosdl: ${SRCS}
	${CC} -DNOSDL ${CFLAGS} -o $@ ${SRCS} ${LIBS}

tiny386_kvm: ${SRCS}
	${CC} -DUSEKVM ${CFLAGS} -o $@ ${SRCS} ${LIBS}

wifikbd: wifikbd.c
	${CC} ${CFLAGS} -o $@ wifikbd.c ${LIBS}

initnet: initnet.c
	${CC} -o $@ initnet.c
