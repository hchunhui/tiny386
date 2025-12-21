Q = @
CC = gcc
CFLAGS = -I . -Os -ffunction-sections -fdata-sections -DLIBSLIRP_STATIC

SRCS = \
slirp/src/ip6_output.c \
slirp/src/udp6.c \
slirp/src/ip6_input.c \
slirp/src/slirp.c \
slirp/src/stream.c \
slirp/src/version.c \
slirp/src/arp_table.c \
slirp/src/mbuf.c \
slirp/src/ndp_table.c \
slirp/src/vmstate.c \
slirp/src/tcp_output.c \
slirp/src/dnssearch.c \
slirp/src/tcp_timer.c \
slirp/src/bootp.c \
slirp/src/tcp_subr.c \
slirp/src/ip_input.c \
slirp/src/sbuf.c \
slirp/src/ip_output.c \
slirp/src/util.c \
slirp/src/ip6_icmp.c \
slirp/src/if.c \
slirp/src/ip_icmp.c \
slirp/src/tftp.c \
slirp/src/misc.c \
slirp/src/state.c \
slirp/src/dhcpv6.c \
slirp/src/ncsi.c \
slirp/src/socket.c \
slirp/src/tcp_input.c \
slirp/src/udp.c \
slirp/src/cksum.c

OBJS = ${SRCS:.c=.o}

.PHONY: all win32 clean install
.SUFFIXES: .c
.c.o:
	@/bin/echo -e " \e[1;32mCC\e[0m\t\e[1;37m$<\e[0m \e[1;32m->\e[0m \e[1;37m$@\e[0m"
	${Q}${CC} ${CFLAGS} -c $< -o $@

all: libslirp.a

win32:
	make -C . CC=i686-w64-mingw32-gcc

libslirp.a: ${OBJS}
	ar rcs $@ $^$>

install:
	mkdir -p ${DESTDIR}/slirp
	cp slirp/src/libslirp.h ${DESTDIR}/slirp
	cp glib.h libslirp-version.h ${DESTDIR}/slirp
	cp libslirp.a ${DESTDIR}/
clean:
	rm -f ${OBJS} libslirp.a
