Q ?= @
CC ?= gcc
SDL_CONFIG = sdl-config
CFLAGS = -O3 -g `${SDL_CONFIG} --cflags`
#CFLAGS = -g `sdl-config --cflags`
LIBS = `${SDL_CONFIG} --libs` -lm
SRCS = ini.c i386.c fpu.c i8259.c i8254.c ide.c vga.c i8042.c misc.c fmopl.c adlib.c ne2000.c i8257.c sb16.c pcspk.c
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

# OSD
SRCS += osd/microui.c osd/osd.c

OBJS = ${SRCS:.c=.o}

PROGS = tiny386 tiny386_nosdl tiny386_kvm wifikbd initnet

.PHONY: all clean dep
.SUFFIXES: .c
.c.o:
	@/bin/echo -e " \e[1;32mCC\e[0m\t\e[1;37m$<\e[0m \e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${CFLAGS} -c $< -o $@

all: ${PROGS}

clean:
	rm -f ${OBJS} .depends ${PROGS}

tiny386: main.c ${OBJS}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${CFLAGS} -o $@ $< ${OBJS} ${LIBS}

tiny386_nosdl: main.c ${OBJS}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} -DNOSDL ${CFLAGS} -o $@ $< ${OBJS} ${LIBS}

tiny386_kvm: main.c kvm.c ${OBJS}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} -DUSEKVM ${CFLAGS} -o $@ $< kvm.c ${OBJS} ${LIBS}

wifikbd: wifikbd.c
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${CFLAGS} -o $@ wifikbd.c ${LIBS}

initnet: initnet.c
	${Q}${CC} -o $@ initnet.c

.depends: ${SRCS}
	@/bin/echo -e " \e[1;32mDEP\e[0m\t\e[1;37m$^$>\e[0m \e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}rm -f $@
	${Q}for i in $^$>; do ${CC} ${CFLAGS} -MT $$(dirname $$i)/$$(basename -s .c $$i).o -MM $$i 2> /dev/null >> $@ || exit 0; done

dep: .depends
-include .depends
