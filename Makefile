Q ?= @
CC ?= gcc
SDL_CONFIG ?= sdl-config
SLIRP_LIB ?= -lslirp
CFLAGS = -I . -O3 -g `${SDL_CONFIG} --cflags` ${SLIRP_INC} ${CFLAGS_PLAT}
LIBS = `${SDL_CONFIG} --libs` -lm ${SLIRP_LIB} ${LIBS_PLAT}

SRCS = ini.c i386.c fpu.c i8259.c i8254.c ide.c vga.c i8042.c misc.c fmopl.c adlib.c ne2000.c i8257.c sb16.c pcspk.c
SRCS += pci.c
SRCS += win32.c

# OSD
SRCS += osd/microui.c osd/osd.c

OBJS = ${SRCS:.c=.o}

PROGS = tiny386 tiny386_nosdl tiny386_kvm wifikbd initnet

.PHONY: all clean dep prepare
.SUFFIXES: .c
.c.o:
	@/bin/echo -e " \e[1;32mCC\e[0m\t\e[1;37m$<\e[0m \e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${CFLAGS} -c $< -o $@

all: ${PROGS}

win32:
	make -C . CC?=i686-w64-mingw32-gcc CFLAGS_PLAT=-mconsole LIBS_PLAT="-lws2_32 -liphlpapi" tiny386 wifikbd

clean:
	rm -f ${OBJS} .depends ${PROGS}

prepare: fmopl.inc

fmopl.inc: fmopl.c
	${CC} -DGENTABLE $^$> -o fmoplgen -lm && ./fmoplgen > $@ && rm -f ./fmoplgen

tiny386: sdl/main.c pc.c ${OBJS}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${CFLAGS} -o $@ $^$> ${LIBS}

tiny386_nosdl: main.c pc.c ${OBJS}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} -DNOSDL ${CFLAGS} -o $@ $^$> ${LIBS}

tiny386_kvm: sdl/main.c kvm.c pc.c ${OBJS}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} -DUSEKVM ${CFLAGS} -o $@ $^$> ${LIBS}

wifikbd: wifikbd.c win32.c
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${CFLAGS} -o $@ wifikbd.c win32.c ${LIBS}

initnet: initnet.c
	${Q}${CC} -o $@ initnet.c

.depends: ${SRCS}
	@/bin/echo -e " \e[1;32mDEP\e[0m\t\e[1;37m$^$>\e[0m \e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}rm -f $@
	${Q}for i in $^$>; do ${CC} ${CFLAGS} -MT $$(dirname $$i)/$$(basename -s .c $$i).o -MM $$i 2> /dev/null >> $@ || exit 0; done

dep: .depends
-include .depends
