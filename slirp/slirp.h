#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>
#include "cutils.h"
#include "slirp_config.h"

#ifdef _WIN32
# include <inttypes.h>

typedef char *caddr_t;

# include <windows.h>
# include <winsock2.h>
# include <ws2tcpip.h>
# include <sys/timeb.h>
# include <iphlpapi.h>

# define EWOULDBLOCK WSAEWOULDBLOCK
# define EINPROGRESS WSAEINPROGRESS
# define ENOTCONN WSAENOTCONN
# define EHOSTUNREACH WSAEHOSTUNREACH
# define ENETUNREACH WSAENETUNREACH
# define ECONNREFUSED WSAECONNREFUSED
#else
# define ioctlsocket ioctl
# define closesocket(s) close(s)
# if !defined(__HAIKU__)
#  define O_BINARY 0
# endif
#endif

#include <sys/types.h>
#ifdef HAVE_SYS_BITYPES_H
# include <sys/bitypes.h>
#endif

#include <sys/time.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#include <stdio.h>
#include <errno.h>

#ifndef HAVE_MEMMOVE
#define memmove(x, y, z) bcopy(y, x, z)
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#else
# include <strings.h>
#endif

#ifndef _WIN32
#include <sys/uio.h>
#endif

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* Systems lacking strdup() definition in <string.h>. */
#if defined(ultrix)
char *strdup(const char *);
#endif

/* Systems lacking malloc() definition in <stdlib.h>. */
#if defined(ultrix) || defined(hcx)
void *malloc(size_t arg);
void free(void *ptr);
#endif

#ifndef HAVE_INET_ATON
int inet_aton(const char *cp, struct in_addr *ia);
#endif

#include <fcntl.h>
#ifndef NO_UNIX_SOCKETS
#include <sys/un.h>
#endif
#include <signal.h>
#ifdef HAVE_SYS_SIGNAL_H
# include <sys/signal.h>
#endif
#ifndef _WIN32
#include <sys/socket.h>
#endif

#if defined(HAVE_SYS_IOCTL_H)
# include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#ifdef USE_PPP
#include <ppp/slirppp.h>
#endif

#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include <sys/stat.h>

/* Avoid conflicting with the libc insque() and remque(), which
   have different prototypes. */
#define insque slirp_insque
#define remque slirp_remque

#ifdef HAVE_SYS_STROPTS_H
#include <sys/stropts.h>
#endif

#include "debug.h"

#include "libslirp.h"
#include "ip.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_var.h"
#include "tcpip.h"
#include "udp.h"
#include "ip_icmp.h"
#include "mbuf.h"
#include "sbuf.h"
#include "socket.h"
#include "if.h"
#include "main.h"
#include "misc.h"
#ifdef USE_PPP
#include "ppp/pppd.h"
#include "ppp/ppp.h"
#endif

#include "bootp.h"
#include "tftp.h"

struct Slirp {
    /* virtual network configuration */
    struct in_addr vnetwork_addr;
    struct in_addr vnetwork_mask;
    struct in_addr vhost_addr;
    struct in_addr vdhcp_startaddr;
    struct in_addr vnameserver_addr;

    /* ARP cache for the guest IP addresses (XXX: allow many entries) */
    uint8_t client_ethaddr[6];

    struct in_addr client_ipaddr;
    char client_hostname[33];

    int restricted;
    struct timeval tt;
    struct ex_list *exec_list;

    /* mbuf states */
    struct mbuf m_freelist, m_usedlist;
    int mbuf_alloced;

    /* if states */
    int if_queued;          /* number of packets queued so far */
    struct mbuf if_fastq;   /* fast queue (for interactive data) */
    struct mbuf if_batchq;  /* queue for non-interactive data */
    struct mbuf *next_m;    /* pointer to next mbuf to output */

    /* ip states */
    struct ipq ipq;         /* ip reass. queue */
    uint16_t ip_id;         /* ip packet ctr, for ids */

    /* bootp/dhcp states */
    BOOTPClient bootp_clients[NB_BOOTP_CLIENTS];
    char *bootp_filename;

    /* tcp states */
    struct socket tcb;
    struct socket *tcp_last_so;
    tcp_seq tcp_iss;        /* tcp initial send seq # */
    uint32_t tcp_now;       /* for RFC 1323 timestamps */

    /* udp states */
    struct socket udb;
    struct socket *udp_last_so;

    /* icmp states */
    struct socket icmp;
    struct socket *icmp_last_so;

    /* tftp states */
    char *tftp_prefix;
    struct tftp_session tftp_sessions[TFTP_SESSIONS_MAX];

    void *opaque;
};

extern Slirp *slirp_instance;

#ifndef NULL
#define NULL (void *)0
#endif

#ifndef FULL_BOLT
void if_start(Slirp *);
#else
void if_start(struct ttys *);
#endif

#ifndef HAVE_STRERROR
 char *strerror(int error);
#endif

#ifndef HAVE_INDEX
 char *index(const char *, int);
#endif

#ifndef HAVE_GETHOSTID
 long gethostid(void);
#endif

void lprint(const char *, ...) __attribute__((format(printf, 1, 2)));

#ifndef _WIN32
#include <netdb.h>
#endif

#define DEFAULT_BAUD 115200

#define SO_OPTIONS DO_KEEPALIVE
#define TCP_MAXIDLE (TCPTV_KEEPCNT * TCPTV_KEEPINTVL)

/* cksum.c */
int cksum(struct mbuf *m, int len);

/* if.c */
void if_init(Slirp *);
void if_output(struct socket *, struct mbuf *);

/* ip_input.c */
void ip_init(Slirp *);
void ip_input(struct mbuf *);
void ip_slowtimo(Slirp *);
void ip_stripoptions(register struct mbuf *, struct mbuf *);

/* ip_output.c */
int ip_output(struct socket *, struct mbuf *);

/* tcp_input.c */
void tcp_input(register struct mbuf *, int, struct socket *);
int tcp_mss(register struct tcpcb *, u_int);

/* tcp_output.c */
int tcp_output(register struct tcpcb *);
void tcp_setpersist(register struct tcpcb *);

/* tcp_subr.c */
void tcp_init(Slirp *);
void tcp_template(struct tcpcb *);
void tcp_respond(struct tcpcb *, register struct tcpiphdr *, register struct mbuf *, tcp_seq, tcp_seq, int);
struct tcpcb * tcp_newtcpcb(struct socket *);
struct tcpcb * tcp_close(register struct tcpcb *);
void tcp_sockclosed(struct tcpcb *);
int tcp_fconnect(struct socket *);
void tcp_connect(struct socket *);
int tcp_attach(struct socket *);
uint8_t tcp_tos(struct socket *);
int tcp_emu(struct socket *, struct mbuf *);
int tcp_ctl(struct socket *);
struct tcpcb *tcp_drop(struct tcpcb *tp, int err);

#ifdef USE_PPP
#define MIN_MRU MINMRU
#define MAX_MRU MAXMRU
#else
#define MIN_MRU 128
#define MAX_MRU 16384
#endif

#ifndef _WIN32
#define min(x,y) ((x) < (y) ? (x) : (y))
#define max(x,y) ((x) > (y) ? (x) : (y))
#endif

#ifdef _WIN32
#undef errno
#define errno (WSAGetLastError())
#endif

#endif
