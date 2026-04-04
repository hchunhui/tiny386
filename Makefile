Q = @
CC_ = gcc
CC_win32 = i686-w64-mingw32-gcc
CC = ${CC_${PLAT}}
HOSTCC = ${CC}

SDL_CONFIG = sdl-config
SLIRP_INC =
SLIRP_LIB = -lslirp

CFLAGS = -I . -Wall -O3 -ffunction-sections -fdata-sections -g -Wl,--gc-sections
CFLAGS += -DI386_ENABLE_FPU
CFLAGS += -DI386_ENABLE_MMX -DI386_ENABLE_SSE -DI386_ENABLE_SSE2 -DI386_ENABLE_SSE3
CFLAGS += -DI386_ENABLE_SSSE3
CFLAGS_SDL = ${CFLAGS} `${SDL_CONFIG} --cflags`

LDFLAGS_ =
LDFLAGS_win32 = -mconsole
LDFLAGS = ${LDFLAGS_${PLAT}}

LIBS = -lm

SRCS =

#USE_GLIBC_FIX = y/n
#build with recent glibc, can run with older glibc (experimental)
USE_GLIBC_FIX = n
CFLAGS_GLIBC_FIX_y = -include glibc-fix/glibc-fix.h
CFLAGS_GLIBC_FIX = ${CFLAGS_GLIBC_FIX_${USE_GLIBC_FIX}}
SRCS_GLIBC_FIX_y = glibc-fix/glibc-fix.c
SRCS_GLIBC_FIX = ${SRCS_GLIBC_FIX_${USE_GLIBC_FIX}}
LIBS_GLIBC_FIX_y = -Wl,--no-as-needed -l:libdl.so.2 -l:libpthread.so.0 -Wl,--as-needed
LIBS_GLIBC_FIX = ${LIBS_GLIBC_FIX_${USE_GLIBC_FIX}}
SRCS += ${SRCS_GLIBC_FIX}
CFLAGS += ${CFLAGS_GLIBC_FIX}
LIBS += ${LIBS_GLIBC_FIX}

LIBS_SDL_ = `${SDL_CONFIG} --libs` ${LIBS}
LIBS_SDL_win32 = `${SDL_CONFIG} --libs` ${LIBS}
LIBS_SDL = ${LIBS_SDL_${PLAT}}

LIBS_RAWDRAW_ = -lX11 -lasound ${LIBS}
LIBS_RAWDRAW_win32 = -lgdi32 -lwinmm ${LIBS}
LIBS_RAWDRAW = ${LIBS_RAWDRAW_${PLAT}}

#USE_SDL = y/n
USE_SDL = n

#USE_FMOPL = y/n
USE_FMOPL = y
FMOPL_y = fmopl.c
CFLAGS_FMOPL_y = -DUSE_FMOPL
CFLAGS += ${CFLAGS_FMOPL_${USE_FMOPL}}

#USE_CPUABS = y/n
USE_CPUABS = n
CPUABS_y = kvm.c
CFLAGS_CPUABS_y = -DUSE_CPUABS
CFLAGS += ${CFLAGS_CPUABS_${USE_CPUABS}}

#USE_SLIRP = y/n
USE_SLIRP = y
CFLAGS_SLIRP_y = -DUSE_SLIRP ${SLIRP_INC}
LIBS_SLIRP_y_ = ${SLIRP_LIB}
LIBS_SLIRP_y_win32 = ${SLIRP_LIB} -lws2_32 -liphlpapi
CFLAGS += ${CFLAGS_SLIRP_${USE_SLIRP}}
LIBS += ${LIBS_SLIRP_${USE_SLIRP}_${PLAT}}

#USE_TUNTAP = y/n
USE_TUNTAP_ = y
USE_TUNTAP_win32 = n
USE_TUNTAP = ${USE_TUNTAP_${PLAT}}
CFLAGS_TUNTAP_y = -DUSE_TUNTAP
CFLAGS += ${CFLAGS_TUNTAP_${USE_TUNTAP}}

SUFF_SDL_SDL_y =
SUFF_SDL_SDL_n = _sdl
SUFF_RAWDRAW_SDL_y = _rawdraw
SUFF_RAWDRAW_SDL_n =
SUFF_SDL = ${SUFF_SDL_SDL_${USE_SDL}}
SUFF_RAWDRAW = ${SUFF_RAWDRAW_SDL_${USE_SDL}}

PROGS_ = tiny386 tiny386_headless wifikbd initnet
PROGS_win32 = tiny386 tiny386_headless wifikbd
PROGS = ${PROGS_${PLAT}}

SRCS += ini.c i386.c fpu.c i8259.c i8254.c ide.c vga.c i8042.c misc.c adlib.c ne2000.c i8257.c sb16.c pcspk.c
SRCS += ${FMOPL_${USE_FMOPL}}
SRCS += ${CPUABS_${USE_CPUABS}}
SRCS += pc.c
SRCS += pci.c
SRCS += win32.c
# OSD
SRCS += osd/microui.c osd/osd.c

OBJS = ${SRCS:.c=.o}

.PHONY: all clean dep prepare
.SUFFIXES: .c
.c.o:
	@/bin/echo -e " \e[1;32mCC\e[0m\t\e[1;37m$<\e[0m \e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${CFLAGS} -c $< -o $@

all: ${PROGS}

win32:
	make -C . PLAT=win32

clean:
	rm -f ${OBJS} .depends ${PROGS}

prepare: fmopl.inc

fmopl.inc: fmopl.c
	${HOSTCC} -DGENTABLE $^$> -o fmoplgen -lm && ./fmoplgen > $@ && rm -f ./fmoplgen

tiny386${SUFF_SDL}: sdl/main.c ${OBJS}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${LDFLAGS} ${CFLAGS_SDL} -o $@ $^$> ${LIBS_SDL}

tiny386${SUFF_RAWDRAW}: rawdraw/main.c ${OBJS}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${LDFLAGS} ${CFLAGS} -o $@ $^$> ${LIBS_RAWDRAW}

tiny386_headless: main.c ${OBJS}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${LDFLAGS} ${CFLAGS} -o $@ $^$> ${LIBS}

wifikbd${SUFF_SDL}: tools/wifikbd.c win32.c ${SRCS_GLIBC_FIX}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${LDFLAGS} ${CFLAGS_SDL} -o $@ $^$> ${LIBS_SDL}

wifikbd${SUFF_RAWDRAW}: rawdraw/wifikbd.c win32.c ${SRCS_GLIBC_FIX}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${LDFLAGS} ${CFLAGS} -o $@ $^$> ${LIBS_RAWDRAW}

initnet: tools/initnet.c ${SRCS_GLIBC_FIX}
	@/bin/echo -e " \e[1;32mCCLD\e[0m\t\e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${CFLAGS_GLIBC_FIX} -o $@ $^$> ${LIBS_GLIBC_FIX}

.depends: ${SRCS}
	@/bin/echo -e " \e[1;32mDEP\e[0m\t\e[1;37m$^$>\e[0m \e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}rm -f $@
	${Q}for i in $^$>; do ${CC} ${CFLAGS} -MT $$(dirname $$i)/$$(basename -s .c $$i).o -MM $$i 2> /dev/null >> $@ || exit 0; done

dep: .depends
-include .depends
